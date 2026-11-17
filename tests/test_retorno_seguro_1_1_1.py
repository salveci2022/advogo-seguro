# -*- coding: utf-8 -*-
"""Versão 1.1.1, pacote B: retorno seguro da 1.2.0.

Tokens de cliente com os campos sid (sessão persistente) ou gs (geração) só são emitidos pela 1.2.0,
que controla revogação por aparelho. Nesta versão eles são recusados, para que um retorno da 1.2.0
não reabra acessos encerrados lá. Tokens convencionais e a autenticação do escritório não mudam.
"""
import pytest

from conftest import appmodule, cliente_ja_criou_senha_pessoal

db = appmodule.db
TELEFONE = '61955511001'
ROTAS_CLIENTE = [
    ('get', '/api/cliente/processos', None),
    ('get', '/api/cliente/contato-seguro/ativo', None),
    ('post', '/api/cliente/verificar', {'numero': '61900000000'}),
    ('get', '/api/cliente/privacidade/exportar', None),
    ('post', '/api/cliente/senha', {'senha_atual': 'x', 'nova_senha': 'OutraSenhaPessoal2026'}),
]


@pytest.fixture()
def cenario(client):
    resp = client.post('/api/escritorio/registro', json={
        'nome': 'Escritorio Retorno', 'email': 'retorno@esc.test', 'senha': 'SenhaSegura123', 'aceite_termos': True})
    assert resp.status_code == 200, resp.get_json()
    with appmodule.app.app_context():
        esc = appmodule.Escritorio.query.filter_by(email='retorno@esc.test').first()
        esc.plano, esc.plano_expira = 'profissional', None
        db.session.commit()
    he = {'Authorization': f"Bearer {resp.get_json()['token']}"}
    adv = client.post('/api/escritorio/advogados', json={'nome': 'Dra. Retorno', 'telefone_oficial': '61911115511'},
                      headers=he).get_json()['id']
    proc = client.post('/api/escritorio/processos', json={
        'advogado_id': adv, 'cliente_nome': 'Cliente Retorno', 'cliente_telefone': TELEFONE}, headers=he).get_json()
    cliente_ja_criou_senha_pessoal(TELEFONE)
    return {'he': he, 'proc': proc, 'cliente_id': proc['cliente_id']}


def token_cliente(cliente_id, **extras):
    with appmodule.app.app_context():
        cli = db.session.get(appmodule.Cliente, cliente_id)
        payload = {'id': cli.id, 'tipo': 'cliente'}
        payload.update(extras)
        token, _ = appmodule.gerar_token(payload, cli.senha_hash)
    return {'Authorization': f'Bearer {token}'}


def chamar(client, metodo, rota, corpo, headers):
    return client.get(rota, headers=headers) if metodo == 'get' else client.post(rota, json=corpo, headers=headers)


# ---------- tokens convencionais continuam funcionando ----------

def test_login_convencional_funciona_e_nao_emite_sid_nem_gs(client, cenario):
    import jwt
    resp = client.post('/api/cliente/login', json={'telefone': TELEFONE, 'senha': cenario['proc']['senha_temporaria']})
    assert resp.status_code == 200
    dados = jwt.decode(resp.get_json()['token'], options={'verify_signature': False})
    assert 'sid' not in dados and 'gs' not in dados
    assert client.get('/api/cliente/processos', headers={'Authorization': f"Bearer {resp.get_json()['token']}"}).status_code == 200


def test_token_convencional_ja_emitido_continua_valido(client, cenario):
    assert client.get('/api/cliente/processos', headers=token_cliente(cenario['cliente_id'])).status_code == 200


# ---------- tokens da 1.2.0 são recusados ----------

@pytest.mark.parametrize('extras', [
    {'sid': 'abc123'}, {'gs': 0}, {'gs': 3}, {'sid': 'abc123', 'gs': 1}, {'sid': ''}, {'gs': None},
])
def test_token_com_sid_ou_gs_e_recusado(client, cenario, extras):
    resp = client.get('/api/cliente/processos', headers=token_cliente(cenario['cliente_id'], **extras))
    assert resp.status_code == 401
    assert resp.get_json()['erro'] == appmodule.MENSAGEM_SESSAO_DE_OUTRA_VERSAO


@pytest.mark.parametrize('metodo,rota,corpo', ROTAS_CLIENTE)
def test_todas_as_rotas_do_cliente_recusam(client, cenario, metodo, rota, corpo):
    resp = chamar(client, metodo, rota, corpo, token_cliente(cenario['cliente_id'], sid='x', gs=0))
    assert resp.status_code == 401


def test_recusa_tambem_pelo_cookie(client, cenario):
    with appmodule.app.app_context():
        cli = db.session.get(appmodule.Cliente, cenario['cliente_id'])
        token, _ = appmodule.gerar_token({'id': cli.id, 'tipo': 'cliente', 'gs': 0}, cli.senha_hash)
    anonimo = appmodule.app.test_client()
    anonimo.set_cookie(appmodule.AUTH_COOKIE_NAME, token)
    assert anonimo.get('/api/cliente/processos').status_code == 401


def test_troca_de_senha_com_token_da_1_2_0_nao_altera_a_senha(client, cenario):
    with appmodule.app.app_context():
        antes = db.session.get(appmodule.Cliente, cenario['cliente_id']).senha_hash
    resp = client.post('/api/cliente/senha', json={'senha_atual': cenario['proc']['senha_temporaria'],
                                                   'nova_senha': 'NovaSenhaRetorno2026'},
                       headers=token_cliente(cenario['cliente_id'], sid='x'))
    assert resp.status_code == 401
    with appmodule.app.app_context():
        assert db.session.get(appmodule.Cliente, cenario['cliente_id']).senha_hash == antes


def test_depois_de_recusado_o_cliente_entra_de_novo(client, cenario):
    assert client.get('/api/cliente/processos', headers=token_cliente(cenario['cliente_id'], sid='x')).status_code == 401
    novo = client.post('/api/cliente/login', json={'telefone': TELEFONE, 'senha': cenario['proc']['senha_temporaria']})
    assert novo.status_code == 200
    assert client.get('/api/cliente/processos', headers={'Authorization': f"Bearer {novo.get_json()['token']}"}).status_code == 200


def test_logout_continua_funcionando_com_token_da_1_2_0(client, cenario):
    assert client.post('/api/logout', headers=token_cliente(cenario['cliente_id'], sid='x', gs=0)).status_code == 200


# ---------- escritório não muda ----------

def test_autenticacao_do_escritorio_nao_e_afetada(client, cenario):
    with appmodule.app.app_context():
        esc = appmodule.Escritorio.query.filter_by(email='retorno@esc.test').first()
        token, _ = appmodule.gerar_token({'id': esc.id, 'tipo': 'escritorio', 'sid': 'x', 'gs': 0}, esc.senha_hash)
    # Mesmo com campos extras, o decorator do escritório segue as regras de sempre.
    assert client.get('/api/escritorio/clientes', headers={'Authorization': f'Bearer {token}'}).status_code == 200
    assert client.get('/api/escritorio/clientes', headers=cenario['he']).status_code == 200


def test_token_de_cliente_nao_acessa_escritorio(client, cenario):
    assert client.get('/api/escritorio/clientes', headers=token_cliente(cenario['cliente_id'])).status_code == 401
