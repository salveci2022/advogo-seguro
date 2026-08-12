# -*- coding: utf-8 -*-
from datetime import timedelta
import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
import app as appmodule

db = appmodule.db
Escritorio = appmodule.Escritorio
Advogado = appmodule.Advogado
Cliente = appmodule.Cliente
Processo = appmodule.Processo
TentativaContato = appmodule.TentativaContato
ContatoSeguro = appmodule.ContatoSeguro
ContatoSeguroLog = appmodule.ContatoSeguroLog
AcessoPublicoLog = appmodule.AcessoPublicoLog


def test_sqlite_foreign_keys_ativadas(client):
    with appmodule.app.app_context():
        assert db.session.execute(text('PRAGMA foreign_keys')).scalar() == 1


def test_indices_essenciais_presentes(client):
    esperados = {
        'advogados': {'ix_advogados_escritorio_ativo', 'ix_advogados_escritorio_oab'},
        'processos': {'ix_processos_escritorio_criado', 'ix_processos_cliente_status', 'ix_processos_advogado_escritorio'},
        'contatos_seguros': {'ix_contatos_escritorio_criado', 'ix_contatos_cliente_status_expira', 'ix_contatos_processo_status_expira', 'ix_contatos_advogado'},
    }
    with appmodule.app.app_context():
        insp = inspect(db.engine)
        for tabela, nomes in esperados.items():
            atuais = {i['name'] for i in insp.get_indexes(tabela)}
            assert nomes.issubset(atuais), (tabela, atuais)


def test_cliente_telefone_unico_no_banco(client):
    with appmodule.app.app_context():
        db.session.add(Cliente(nome='Cliente 1', telefone='61999990000', email='c1@teste.com', senha_hash='hash-1'))
        db.session.commit()
        db.session.add(Cliente(nome='Cliente 2', telefone='61999990000', email='c2@teste.com', senha_hash='hash-2'))
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()


def test_fk_rejeita_processo_orfao(client):
    with appmodule.app.app_context():
        with pytest.raises(IntegrityError):
            db.session.execute(text("INSERT INTO processos (escritorio_id, advogado_id, cliente_id, codigo_unico, status, criado_em) VALUES (99991,99992,99993,'ORFAO123','ativo',CURRENT_TIMESTAMP)"))
            db.session.commit()
        db.session.rollback()


def test_delete_escritorio_cascade_no_banco(client):
    with appmodule.app.app_context():
        e = Escritorio(nome='Escritório DB', email='db@teste.com', senha_hash='hash', plano='trial', plano_expira=appmodule.agora_utc()+timedelta(days=1))
        db.session.add(e); db.session.flush()
        a = Advogado(escritorio_id=e.id, nome='Advogado DB', oab='OAB/DF 999', telefone_oficial='61999991111')
        c = Cliente(nome='Cliente DB', telefone='61999992222', email='cliente-db@teste.com', senha_hash='hash')
        db.session.add_all([a,c]); db.session.flush()
        p = Processo(escritorio_id=e.id, advogado_id=a.id, cliente_id=c.id, codigo_unico='DBCAS123', status='ativo')
        db.session.add(p); db.session.flush()
        t = TentativaContato(processo_id=p.id, descricao='Teste')
        cs = ContatoSeguro(escritorio_id=e.id, advogado_id=a.id, cliente_id=c.id, processo_id=p.id, codigo_cca='CCA-DB-1234', canal='whatsapp', status='ativo', expira_em=appmodule.agora_utc()+timedelta(minutes=10))
        al = AcessoPublicoLog(processo_id=p.id, acao='visualizou')
        db.session.add_all([t,cs,al]); db.session.flush()
        log = ContatoSeguroLog(cliente_id=c.id, contato_seguro_id=cs.id, encontrado_ativo=True)
        db.session.add(log); db.session.commit()
        ids = {'e':e.id,'a':a.id,'c':c.id,'p':p.id,'t':t.id,'cs':cs.id,'log':log.id,'al':al.id}
        db.session.execute(text('DELETE FROM escritorios WHERE id=:id'), {'id':ids['e']}); db.session.commit()
        assert db.session.get(Advogado, ids['a']) is None
        assert db.session.get(Processo, ids['p']) is None
        assert db.session.get(TentativaContato, ids['t']) is None
        assert db.session.get(ContatoSeguro, ids['cs']) is None
        assert db.session.get(ContatoSeguroLog, ids['log']) is None
        assert db.session.get(AcessoPublicoLog, ids['al']) is None
        assert db.session.get(Cliente, ids['c']) is not None


def test_migracao_indices_e_idempotente(client):
    with appmodule.app.app_context():
        appmodule._garantir_indices_banco()
        appmodule._garantir_indices_banco()


def test_integridade_sqlite_sem_orfaos(client):
    with appmodule.app.app_context():
        assert db.session.execute(text('PRAGMA integrity_check')).scalar() == 'ok'
        assert db.session.execute(text('PRAGMA foreign_key_check')).fetchall() == []


def test_colunas_ativo_presentes(client):
    with appmodule.app.app_context():
        insp = inspect(db.engine)
        assert 'ativo' in {c['name'] for c in insp.get_columns('advogados')}
        assert 'ativo' in {c['name'] for c in insp.get_columns('clientes')}
