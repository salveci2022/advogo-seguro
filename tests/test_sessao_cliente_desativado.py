# -*- coding: utf-8 -*-
"""Etapa 1 (sessão do cliente): cliente com ativo=False não usa sessão já aberta.

Antes da correção, desativar o cliente só bloqueava NOVOS logins; o JWT emitido
antes continuava aceito por login_cliente_obrigatorio até expirar (até 12 h).
Um aparelho perdido com sessão aberta seguia com acesso mesmo após o escritório
desativar o cliente.
"""
import pytest

from conftest import appmodule, cliente_ja_criou_senha_pessoal

TELEFONE = '61977770001'
MENSAGEM_DESATIVADO = 'Acesso do cliente desativado. Entre em contato com o escritório responsável.'

ROTAS_CLIENTE = [
    ('get', '/api/cliente/processos', None),
    ('get', '/api/cliente/contato-seguro/ativo', None),
    ('post', '/api/cliente/contato-seguro/verificar', {}),
    ('post', '/api/cliente/contato-seguro/registrar-suspeita', {}),
    ('post', '/api/cliente/verificar', {'numero': '61900000000'}),
    ('post', '/api/cliente/autorizar-escritorio', {'email_escritorio': 'x@x.com'}),
    ('get', '/api/cliente/privacidade/exportar', None),
    ('get', '/api/cliente/privacidade/solicitacoes', None),
    # Única rota liberada com troca de senha pendente: também precisa respeitar a desativação.
    ('post', '/api/cliente/senha', {'senha_atual': 'x', 'nova_senha': 'OutraSenhaPessoal2026'}),
]


def registrar_escritorio(client, email='titular@esc-desativado.com'):
    resp = client.post('/api/escritorio/registro', json={
        'nome': 'Escritorio Desativacao', 'email': email, 'senha': 'SenhaSegura123',
        'aceite_termos': True,
    })
    assert resp.status_code == 200, resp.get_json()
    with appmodule.app.app_context():
        escritorio = appmodule.Escritorio.query.filter_by(email=email).first()
        escritorio.plano = 'profissional'
        escritorio.plano_expira = None
        appmodule.db.session.commit()
    return {'Authorization': f"Bearer {resp.get_json()['token']}"}


def montar(client, senha_pessoal_criada=True):
    he = registrar_escritorio(client)
    adv = client.post('/api/escritorio/advogados', json={
        'nome': 'Dra. Responsavel', 'telefone_oficial': '61911117777'
    }, headers=he).get_json()['id']
    proc = client.post('/api/escritorio/processos', json={
        'advogado_id': adv, 'cliente_nome': 'Cliente Desativado', 'cliente_telefone': TELEFONE,
    }, headers=he).get_json()
    if senha_pessoal_criada:
        cliente_ja_criou_senha_pessoal(TELEFONE)
    login = client.post('/api/cliente/login', json={'telefone': TELEFONE, 'senha': proc['senha_temporaria']})
    assert login.status_code == 200, login.get_json()
    hc = {'Authorization': f"Bearer {login.get_json()['token']}"}
    return he, hc, proc


def chamar(client, metodo, rota, corpo, headers=None):
    if metodo == 'get':
        return client.get(rota, headers=headers or {})
    return client.post(rota, json=corpo, headers=headers or {})


def desativar(client, he, cliente_id):
    resp = client.post(f'/api/escritorio/clientes/{cliente_id}/desativar', headers=he)
    assert resp.status_code == 200, resp.get_json()


def test_cliente_ativo_continua_acessando_normalmente(client):
    _, hc, _ = montar(client)
    resp = client.get('/api/cliente/processos', headers=hc)
    assert resp.status_code == 200
    assert len(resp.get_json()) == 1


@pytest.mark.parametrize('metodo,rota,corpo', ROTAS_CLIENTE)
def test_sessao_aberta_e_recusada_apos_desativacao(client, metodo, rota, corpo):
    he, hc, proc = montar(client)
    desativar(client, he, proc['cliente_id'])

    resp = chamar(client, metodo, rota, corpo, hc)

    assert resp.status_code == 401
    assert resp.get_json()['erro'] == MENSAGEM_DESATIVADO
    assert resp.get_json().get('acesso_desativado') is True


def test_sessao_por_cookie_tambem_e_recusada_apos_desativacao(client):
    he, _, proc = montar(client)
    # O test client guardou os cookies HttpOnly do login; nenhuma credencial Bearer é enviada.
    assert client.get('/api/cliente/processos').status_code == 200

    desativar(client, he, proc['cliente_id'])

    assert client.get('/api/cliente/processos').status_code == 401


def test_desativacao_vale_mesmo_com_troca_de_senha_pendente(client):
    he, hc, proc = montar(client, senha_pessoal_criada=False)
    desativar(client, he, proc['cliente_id'])

    resp = client.post('/api/cliente/senha', json={
        'senha_atual': proc['senha_temporaria'], 'nova_senha': 'OutraSenhaPessoal2026'
    }, headers=hc)

    assert resp.status_code == 401
    with appmodule.app.app_context():
        cliente = appmodule.db.session.get(appmodule.Cliente, proc['cliente_id'])
        assert cliente.troca_senha_obrigatoria is True  # a senha não foi trocada


def test_reativacao_restaura_o_acesso(client):
    he, hc, proc = montar(client)
    desativar(client, he, proc['cliente_id'])
    assert client.get('/api/cliente/processos', headers=hc).status_code == 401

    assert client.post(f"/api/escritorio/clientes/{proc['cliente_id']}/reativar", headers=he).status_code == 200

    assert client.get('/api/cliente/processos', headers=hc).status_code == 200


def test_novo_login_de_cliente_desativado_continua_bloqueado(client):
    he, _, proc = montar(client)
    desativar(client, he, proc['cliente_id'])
    resp = client.post('/api/cliente/login', json={'telefone': TELEFONE, 'senha': proc['senha_temporaria']})
    assert resp.status_code == 403
    assert resp.get_json()['erro'] == MENSAGEM_DESATIVADO


def test_autenticacao_do_escritorio_nao_e_afetada(client):
    he, _, proc = montar(client)
    desativar(client, he, proc['cliente_id'])

    clientes = client.get('/api/escritorio/clientes', headers=he)
    assert clientes.status_code == 200
    assert any(c['id'] == proc['cliente_id'] and c['ativo'] is False for c in clientes.get_json())
