# -*- coding: utf-8 -*-
"""Testes da Camada 6 — Performance.

Os testes contam consultas SQL para detectar regressões N+1 sem depender de
cronômetros, que variam muito entre computadores.
"""
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

from sqlalchemy import event

import app as appmodule


db = appmodule.db
Escritorio = appmodule.Escritorio
Advogado = appmodule.Advogado
Cliente = appmodule.Cliente
Processo = appmodule.Processo
TentativaContato = appmodule.TentativaContato
ContatoSeguro = appmodule.ContatoSeguro


@contextmanager
def contar_sql():
    comandos = []

    def antes_cursor(conn, cursor, statement, parameters, context, executemany):
        texto = statement.lstrip().upper()
        if not texto.startswith('PRAGMA'):
            comandos.append(statement)

    engine = db.engine
    event.listen(engine, 'before_cursor_execute', antes_cursor)
    try:
        yield comandos
    finally:
        event.remove(engine, 'before_cursor_execute', antes_cursor)


def criar_massa():
    """Cria volume suficiente para revelar N+1 sem usar dados reais."""
    e = Escritorio(
        nome='Escritório Performance',
        email='perf@teste.com',
        senha_hash=appmodule.hash_senha('TesteSenha123!'),
        plano='trial',
        plano_expira=appmodule.agora_utc() + timedelta(days=10),
    )
    db.session.add(e)
    db.session.flush()

    a = Advogado(
        escritorio_id=e.id,
        nome='Advogado Performance',
        oab='OAB/DF PERF',
        telefone_oficial='61999990001',
    )
    db.session.add(a)
    db.session.flush()

    clientes = []
    processos = []
    for i in range(15):
        c = Cliente(
            nome=f'Cliente Performance {i}',
            telefone=f'6198{i:07d}',
            email=f'cliente{i}@teste.com',
            senha_hash=appmodule.hash_senha('TesteSenha123!'),
        )
        db.session.add(c)
        db.session.flush()
        p = Processo(
            escritorio_id=e.id,
            advogado_id=a.id,
            cliente_id=c.id,
            codigo_unico=f'P{i:011d}',
            token_cliente=f'token-perf-{i}',
            status='ativo',
        )
        db.session.add(p)
        db.session.flush()
        db.session.add(TentativaContato(
            processo_id=p.id,
            numero_suspeito=f'6197{i:07d}',
            canal='whatsapp',
            descricao='Teste de performance',
        ))
        db.session.add(ContatoSeguro(
            escritorio_id=e.id,
            advogado_id=a.id,
            cliente_id=c.id,
            processo_id=p.id,
            codigo_cca=f'CCA-PERF-{i:03d}',
            canal='whatsapp',
            status='ativo',
            expira_em=appmodule.agora_utc() - timedelta(minutes=1),
        ))
        clientes.append(c)
        processos.append(p)

    # Mais processos para o primeiro cliente: detecta N+1 na área do cliente.
    for i in range(15, 25):
        p = Processo(
            escritorio_id=e.id,
            advogado_id=a.id,
            cliente_id=clientes[0].id,
            codigo_unico=f'P{i:011d}',
            token_cliente=f'token-perf-{i}',
            status='ativo',
        )
        db.session.add(p)

    db.session.commit()
    token_escritorio, _ = appmodule.gerar_token(
        {'id': e.id, 'tipo': 'escritorio'}, e.senha_hash
    )
    token_cliente, _ = appmodule.gerar_token(
        {'id': clientes[0].id, 'tipo': 'cliente'}, clientes[0].senha_hash
    )
    db.session.remove()
    return token_escritorio, token_cliente


def _auth(token):
    return {'Authorization': f'Bearer {token}'}


def test_lista_processos_sem_n_mais_1(client):
    with appmodule.app.app_context():
        token, _ = criar_massa()
        with contar_sql() as comandos:
            resp = client.get('/api/escritorio/processos', headers=_auth(token))
        assert resp.status_code == 200
        assert len(resp.get_json()) == 25
        assert len(comandos) <= 5, f'Consultas demais: {len(comandos)}'


def test_lista_clientes_sem_n_mais_1(client):
    with appmodule.app.app_context():
        token, _ = criar_massa()
        with contar_sql() as comandos:
            resp = client.get('/api/escritorio/clientes', headers=_auth(token))
        assert resp.status_code == 200
        assert len(resp.get_json()) == 15
        assert len(comandos) <= 5, f'Consultas demais: {len(comandos)}'


def test_lista_tentativas_sem_n_mais_1(client):
    with appmodule.app.app_context():
        token, _ = criar_massa()
        with contar_sql() as comandos:
            resp = client.get('/api/escritorio/tentativas', headers=_auth(token))
        assert resp.status_code == 200
        assert len(resp.get_json()) == 15
        assert len(comandos) <= 5, f'Consultas demais: {len(comandos)}'


def test_lista_contato_seguro_sem_n_mais_1(client):
    with appmodule.app.app_context():
        token, _ = criar_massa()
        with contar_sql() as comandos:
            resp = client.get('/api/escritorio/contato-seguro/listar', headers=_auth(token))
        assert resp.status_code == 200
        assert len(resp.get_json()) == 15
        assert len(comandos) <= 5, f'Consultas demais: {len(comandos)}'


def test_area_cliente_processos_sem_n_mais_1(client):
    with appmodule.app.app_context():
        _, token = criar_massa()
        with contar_sql() as comandos:
            resp = client.get('/api/cliente/processos', headers=_auth(token))
        assert resp.status_code == 200
        assert len(resp.get_json()) == 11
        assert len(comandos) <= 5, f'Consultas demais: {len(comandos)}'


def test_limpar_expirados_usa_update_em_lote(client):
    with appmodule.app.app_context():
        token, _ = criar_massa()
        with contar_sql() as comandos:
            resp = client.post('/api/escritorio/contato-seguro/limpar-expirados', headers=_auth(token))
        assert resp.status_code == 200
        assert resp.get_json()['marcados_como_expirados'] == 15
        assert len(comandos) <= 5, f'Consultas demais: {len(comandos)}'


def test_cache_estatico_e_otimizacao_de_foto_presentes(client, monkeypatch):
    monkeypatch.setattr(appmodule, 'IS_PRODUCTION', True)
    resp = client.get('/static/css/style.css')
    assert resp.status_code == 200
    assert 'max-age=3600' in resp.headers.get('Cache-Control', '')

    html = client.get('/escritorio/advogados').get_data(as_text=True)
    assert 'prepararFotoOtimizada' in html
    assert "canvas.toBlob(resolve, 'image/webp', 0.82)" in html
