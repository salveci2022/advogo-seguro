# -*- coding: utf-8 -*-
"""RR2: autorização expressa do cliente para vínculo com outro escritório ou recadastro.

O código é emitido só pelo cliente autenticado, vale para um único escritório, expira,
é consumido uma única vez (inclusive com requisições simultâneas) e o banco guarda só o hash.
"""
import logging
import os
import tempfile
import threading
from datetime import timedelta

from sqlalchemy import create_engine, update
from sqlalchemy.exc import SQLAlchemyError

from conftest import appmodule, cliente_ja_criou_senha_pessoal

TELEFONE = '61988880001'
NOME_REAL = 'Maria Titular da Silva'
EMAIL_REAL = 'maria.titular@cliente-a.com'
EMAIL_B = 'outro@escritorio-b.com'


def registrar(client, email):
    resp = client.post('/api/escritorio/registro', json={
        'nome': f'Escritorio {email}', 'email': email, 'senha': 'SenhaSegura123'
    })
    assert resp.status_code == 200, resp.get_json()
    with appmodule.app.app_context():
        escritorio = appmodule.Escritorio.query.filter_by(email=email).first()
        escritorio.plano = 'profissional'
        escritorio.plano_expira = None
        appmodule.db.session.commit()
    return {'Authorization': f"Bearer {resp.get_json()['token']}"}


def criar_advogado(client, headers, telefone_oficial, nome='Dra. Responsavel'):
    resp = client.post('/api/escritorio/advogados', json={
        'nome': nome, 'telefone_oficial': telefone_oficial
    }, headers=headers)
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()['id']


def post_processo(client, headers, advogado_id, telefone=TELEFONE, codigo=None, nome='Nome digitado por B'):
    corpo = {'advogado_id': advogado_id, 'cliente_nome': nome, 'cliente_telefone': telefone}
    if codigo is not None:
        corpo['codigo_autorizacao'] = codigo
    return client.post('/api/escritorio/processos', json=corpo, headers=headers)


def login_cliente(client, senha, telefone=TELEFONE):
    cliente_ja_criou_senha_pessoal(telefone)
    resp = client.post('/api/cliente/login', json={'telefone': telefone, 'senha': senha})
    assert resp.status_code == 200, resp.get_json()
    return {'Authorization': f"Bearer {resp.get_json()['token']}"}


def autorizar(client, hc, email_escritorio):
    previa = client.post('/api/cliente/autorizar-escritorio', json={'email_escritorio': email_escritorio}, headers=hc)
    assert previa.status_code == 200, previa.get_json()
    assert 'codigo' not in previa.get_json()
    resp = client.post('/api/cliente/autorizar-escritorio',
                       json={'email_escritorio': email_escritorio, 'confirmar': True}, headers=hc)
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()['codigo']


def cenario(client):
    ha = registrar(client, 'titular@escritorio-a.com')
    adv_a = criar_advogado(client, ha, '61911110000')
    proc_a = client.post('/api/escritorio/processos', json={
        'advogado_id': adv_a, 'cliente_nome': NOME_REAL, 'cliente_telefone': TELEFONE, 'cliente_email': EMAIL_REAL,
    }, headers=ha)
    assert proc_a.status_code == 200, proc_a.get_json()
    proc_a = proc_a.get_json()
    hb = registrar(client, EMAIL_B)
    adv_b = criar_advogado(client, hb, '61922220000', 'Dr. B')
    hc = login_cliente(client, proc_a['senha_temporaria'])
    return ha, hb, hc, proc_a, adv_a, adv_b


def processos_do_cliente(cliente_id):
    with appmodule.app.app_context():
        return sorted((p.escritorio_id, p.id) for p in appmodule.Processo.query.filter_by(cliente_id=cliente_id))


def autorizacoes():
    with appmodule.app.app_context():
        return appmodule.AutorizacaoVinculo.query.order_by(appmodule.AutorizacaoVinculo.id).all()


# 1 ---------- autorização válida + R1 preservado + cliente em dois escritórios ----------

def test_autorizacao_valida_vincula_sem_expor_dados_do_titular(client):
    ha, hb, hc, proc_a, _, adv_b = cenario(client)
    assert post_processo(client, hb, adv_b).status_code == 409

    codigo = autorizar(client, hc, EMAIL_B)
    resp = post_processo(client, hb, adv_b, codigo=codigo)

    assert resp.status_code == 200, resp.get_json()
    dados = resp.get_json()
    assert dados['cliente_id'] == proc_a['cliente_id']
    assert dados['senha_temporaria'] is None
    assert dados['cliente_nome'] == appmodule.CLIENTE_NOME_PROTEGIDO
    lista_b = client.get('/api/escritorio/processos', headers=hb).get_data(as_text=True)
    assert NOME_REAL not in lista_b and EMAIL_REAL not in lista_b
    assert proc_a['codigo_unico'] not in lista_b
    escritorios = {p['escritorio_nome'] for p in client.get('/api/cliente/processos', headers=hc).get_json()}
    assert len(escritorios) == 2
    autorizacao = autorizacoes()[0]
    assert autorizacao.usado_em is not None and autorizacao.processo_id == dados['id']


# 2 ---------- código de B não serve para C ----------

def test_codigo_nao_serve_para_outro_escritorio(client):
    _, hb, hc, proc_a, _, _ = cenario(client)
    hcx = registrar(client, 'terceiro@escritorio-c.com')
    adv_c = criar_advogado(client, hcx, '61933330000', 'Dr. C')
    codigo = autorizar(client, hc, EMAIL_B)

    resp = post_processo(client, hcx, adv_c, codigo=codigo)

    assert resp.status_code == 409 and resp.get_json()['vinculo_bloqueado'] is True
    assert {e for e, _ in processos_do_cliente(proc_a['cliente_id'])} == {1}
    assert autorizacoes()[0].usado_em is None


# 3 ---------- código de um cliente não serve para outro telefone ----------

def test_codigo_nao_serve_para_outro_telefone(client):
    ha, hb, hc, proc_a, adv_a, adv_b = cenario(client)
    outro = client.post('/api/escritorio/processos', json={
        'advogado_id': adv_a, 'cliente_nome': 'Outro Cliente', 'cliente_telefone': '61977770000',
    }, headers=ha)
    assert outro.status_code == 200
    codigo = autorizar(client, hc, EMAIL_B)

    resp = post_processo(client, hb, adv_b, telefone='61977770000', codigo=codigo)

    assert resp.status_code == 409
    assert autorizacoes()[0].usado_em is None


# 4 ---------- código expirado ----------

def test_codigo_expirado_e_recusado(client, monkeypatch):
    _, hb, hc, proc_a, _, adv_b = cenario(client)
    codigo = autorizar(client, hc, EMAIL_B)
    real = appmodule.agora_utc
    monkeypatch.setattr(appmodule, 'agora_utc', lambda: real() + timedelta(
        minutes=appmodule.AUTORIZACAO_VINCULO_TTL_MINUTOS, seconds=1))

    resp = post_processo(client, hb, adv_b, codigo=codigo)

    assert resp.status_code == 409
    assert len(processos_do_cliente(proc_a['cliente_id'])) == 1


# 5 ---------- código inventado/adulterado + limite de tentativas ----------

def test_codigo_invalido_e_limite_de_tentativas(client):
    _, hb, hc, _, _, adv_b = cenario(client)
    codigo = autorizar(client, hc, EMAIL_B)
    adulterado = ('A' if codigo[0] != 'A' else 'B') + codigo[1:]

    respostas = [post_processo(client, hb, adv_b, codigo=c).status_code
                 for c in [adulterado, 'ZZZZZ-ZZZZZ', '', 'curto', adulterado]]
    assert respostas == [409] * 5
    # 6ª tentativa: bloqueada pelo limite antes de validar, mesmo com o código correto
    assert post_processo(client, hb, adv_b, codigo=codigo).status_code == 429
    assert autorizacoes()[0].usado_em is None


# 6 ---------- reutilização ----------

def test_codigo_nao_pode_ser_reutilizado(client):
    _, hb, hc, proc_a, _, adv_b = cenario(client)
    codigo = autorizar(client, hc, EMAIL_B)
    assert post_processo(client, hb, adv_b, codigo=codigo).status_code == 200
    with appmodule.app.app_context():
        appmodule.Processo.query.filter_by(escritorio_id=2).delete()
        appmodule.db.session.commit()

    resp = post_processo(client, hb, adv_b, codigo=codigo)

    assert resp.status_code == 409
    assert {e for e, _ in processos_do_cliente(proc_a['cliente_id'])} == {1}


def test_nova_autorizacao_cancela_a_anterior(client):
    _, hb, hc, _, _, adv_b = cenario(client)
    primeiro = autorizar(client, hc, EMAIL_B)
    segundo = autorizar(client, hc, EMAIL_B)

    assert post_processo(client, hb, adv_b, codigo=primeiro).status_code == 409
    assert post_processo(client, hb, adv_b, codigo=segundo).status_code == 200


# 7 ---------- concorrência real: duas conexões consumindo o mesmo código ----------

def test_consumo_simultaneo_so_uma_conexao_consegue(client):
    pasta = tempfile.mkdtemp()
    engine = create_engine(f"sqlite:///{os.path.join(pasta, 'concorrencia.db')}",
                           connect_args={'timeout': 15, 'check_same_thread': False})
    try:
        appmodule.db.metadata.create_all(engine)
        agora = appmodule.agora_utc()
        with engine.begin() as con:
            con.execute(appmodule.Escritorio.__table__.insert().values(
                id=1, nome='Esc', email='esc@teste.com', senha_hash='x', assinatura_status='ativa'))
            con.execute(appmodule.Cliente.__table__.insert().values(
                id=1, nome='Cli', telefone='61900000000', senha_hash='x', ativo=True))
            with appmodule.app.app_context():
                codigo_hash = appmodule._hash_codigo_autorizacao('ABCDE23456')
            con.execute(appmodule.AutorizacaoVinculo.__table__.insert().values(
                cliente_id=1, escritorio_id=1, codigo_hash=codigo_hash,
                criado_em=agora, expira_em=agora + timedelta(minutes=15)))

        with appmodule.app.app_context():
            filtro = appmodule._filtro_consumo_autorizacao(codigo_hash, 1, 1, agora).whereclause
        comando = update(appmodule.AutorizacaoVinculo).where(filtro).values(usado_em=agora)
        largada = threading.Barrier(2)
        resultados, erros = [], []

        def consumir():
            try:
                with engine.connect() as con:
                    largada.wait()
                    resultados.append(con.execute(comando).rowcount)
                    con.commit()
            except Exception as erro:  # noqa: BLE001
                erros.append(repr(erro))

        threads = [threading.Thread(target=consumir) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(30)

        assert erros == []
        assert sorted(resultados) == [0, 1]
        with engine.connect() as con:
            usados = con.execute(appmodule.AutorizacaoVinculo.__table__.select()).fetchall()
        assert len(usados) == 1 and usados[0].usado_em is not None
    finally:
        engine.dispose()


# 8 ---------- rollback completo ----------

def test_falha_ao_salvar_desfaz_processo_e_consumo(client, monkeypatch):
    _, hb, hc, proc_a, _, adv_b = cenario(client)
    codigo = autorizar(client, hc, EMAIL_B)

    def commit_com_falha():
        raise SQLAlchemyError('falha simulada')
    monkeypatch.setattr(appmodule.db.session, 'commit', commit_com_falha)
    resp = post_processo(client, hb, adv_b, codigo=codigo)
    monkeypatch.undo()

    assert resp.status_code == 500
    assert len(processos_do_cliente(proc_a['cliente_id'])) == 1
    assert autorizacoes()[0].usado_em is None
    # o mesmo código continua válido depois da falha
    assert post_processo(client, hb, adv_b, codigo=codigo).status_code == 200


# 9 ---------- recadastro legítimo, sem apagar dados ----------

def test_recadastro_exige_autorizacao_e_preserva_cadastro(client):
    ha, _, hc, proc_a, adv_a, _ = cenario(client)
    with appmodule.app.app_context():
        antes = appmodule.db.session.get(appmodule.Cliente, proc_a['cliente_id'])
        antes = (antes.nome, antes.telefone, antes.email, antes.senha_hash)
    assert client.delete(f"/api/escritorio/processos/{proc_a['id']}", headers=ha).status_code == 200
    assert processos_do_cliente(proc_a['cliente_id']) == []

    assert post_processo(client, ha, adv_a).status_code == 409
    codigo = autorizar(client, hc, 'titular@escritorio-a.com')
    resp = post_processo(client, ha, adv_a, codigo=codigo)

    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()['cliente_id'] == proc_a['cliente_id']
    with appmodule.app.app_context():
        depois = appmodule.db.session.get(appmodule.Cliente, proc_a['cliente_id'])
        assert (depois.nome, depois.telefone, depois.email, depois.senha_hash) == antes


# 10 ---------- só o cliente autenticado autoriza ----------

def test_somente_cliente_autenticado_emite_codigo(client):
    _, hb, _, _, _, _ = cenario(client)
    client.delete_cookie(appmodule.AUTH_COOKIE_NAME)
    corpo = {'email_escritorio': EMAIL_B, 'confirmar': True}

    assert client.post('/api/cliente/autorizar-escritorio', json=corpo).status_code == 401
    assert client.post('/api/cliente/autorizar-escritorio', json=corpo, headers=hb).status_code == 401
    assert autorizacoes() == []


# 11 ---------- escritório inexistente e limite de emissões ----------

def test_escritorio_inexistente_e_limite_de_emissoes(client):
    _, _, hc, _, _, _ = cenario(client)
    inexistente = client.post('/api/cliente/autorizar-escritorio',
                              json={'email_escritorio': 'nao-existe@x.com', 'confirmar': True}, headers=hc)
    assert inexistente.status_code == 404
    assert set(inexistente.get_json()) == {'erro'}

    status = [client.post('/api/cliente/autorizar-escritorio',
                          json={'email_escritorio': EMAIL_B, 'confirmar': True}, headers=hc).status_code
              for _ in range(appmodule.AUTORIZACAO_VINCULO_MAX_POR_HORA + 1)]
    assert status == [200] * appmodule.AUTORIZACAO_VINCULO_MAX_POR_HORA + [429]


# 12 ---------- logs e banco sem dados pessoais nem código ----------

def test_logs_e_banco_sem_dados_pessoais_nem_codigo(client, caplog):
    _, hb, hc, _, _, adv_b = cenario(client)
    caplog.set_level(logging.INFO)
    codigo = autorizar(client, hc, EMAIL_B)
    post_processo(client, hb, adv_b, codigo='ZZZZZ-ZZZZZ')
    assert post_processo(client, hb, adv_b, codigo=codigo).status_code == 200

    texto = caplog.text
    assert 'autorizacao_emitida' in texto and 'vinculo_autorizado' in texto and 'autorizacao_recusada' in texto
    for sensivel in (TELEFONE, NOME_REAL, EMAIL_REAL, EMAIL_B, codigo, codigo.replace('-', '')):
        assert sensivel not in texto
    autorizacao = autorizacoes()[0]
    assert len(autorizacao.codigo_hash) == 64
    assert codigo.replace('-', '') not in autorizacao.codigo_hash
