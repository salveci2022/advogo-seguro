# -*- coding: utf-8 -*-
"""Cobertura funcional principal do ADVOGO SEGURO — Camada 1 da auditoria.

Usa o fixture client de tests/conftest.py, que aponta DATABASE_URL para
SQLite em memória e não toca em banco real.
"""
from urllib.parse import urlparse

from conftest import appmodule


def post(client, path, body=None, token=None):
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    return client.post(path, json=body or {}, headers=headers)


def get(client, path, token=None):
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    return client.get(path, headers=headers)


def put(client, path, body=None, token=None):
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    return client.put(path, json=body or {}, headers=headers)


def registrar(client, email='camada1@teste.com', ativar=True):
    resp = post(client, '/api/escritorio/registro', {
        'nome': 'Escritorio Camada 1',
        'email': email,
        'senha': 'SenhaTeste123',
        'cnpj': ''
    })
    assert resp.status_code == 200, resp.get_json()

    if ativar:
        with appmodule.app.app_context():
            escritorio = appmodule.Escritorio.query.filter_by(email=email).first()
            assert escritorio is not None
            escritorio.plano = 'profissional'
            escritorio.plano_expira = None
            appmodule.db.session.commit()

    return resp.get_json()

def criar_advogado(client, token, nome='Dra. Teste', telefone='61999990000'):
    resp = post(client, '/api/escritorio/advogados', {
        'nome': nome,
        'oab': 'OAB/DF 12345',
        'telefone_oficial': telefone,
    }, token)
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()['id']


def criar_processo(client, token, adv_id, telefone='61988887777', nome='Cliente Camada 1'):
    return post(client, '/api/escritorio/processos', {
        'advogado_id': adv_id,
        'cliente_nome': nome,
        'cliente_telefone': telefone,
        'cliente_email': 'cliente@teste.com',
        'numero_processo': '0000000-00.2026.0.00.0000',
        'descricao': 'Teste funcional'
    }, token)


def test_registro_login_e_plano_inativo(client):
    cadastro = registrar(client, ativar=False)
    assert cadastro['plano'] == 'trial'
    assert cadastro['plano_ativo'] is False

    login = post(client, '/api/escritorio/login', {
        'email': 'camada1@teste.com', 'senha': 'SenhaTeste123'
    })
    assert login.status_code == 200, login.get_json()
    token = login.get_json()['token']

    plano = get(client, '/api/escritorio/plano', token).get_json()
    assert plano['codigo'] == 'trial'
    assert plano['limite_advogados'] == 1
    assert plano['pode_adicionar_advogado'] is False


def test_email_duplicado_rejeitado(client):
    registrar(client)
    resp = post(client, '/api/escritorio/registro', {
        'nome': 'Outro', 'email': 'camada1@teste.com', 'senha': 'SenhaTeste123'
    })
    assert resp.status_code == 409


def test_limite_profissional_de_um_advogado(client):
    token = registrar(client)['token']
    criar_advogado(client, token)
    resp = post(client, '/api/escritorio/advogados', {
        'nome': 'Segundo advogado', 'telefone_oficial': '61999991111'
    }, token)
    assert resp.status_code == 403
    assert resp.get_json().get('limite_plano') is True


def test_processo_rejeita_advogado_de_outro_escritorio(client):
    token_a = registrar(client, 'a@teste.com')['token']
    token_b = registrar(client, 'b@teste.com')['token']
    adv_a = criar_advogado(client, token_a)

    resp = criar_processo(client, token_b, adv_a, telefone='61977770001')
    assert resp.status_code == 404
    assert 'neste escritório' in resp.get_json()['erro']


def test_processo_valida_cliente_e_advogado(client):
    token = registrar(client)['token']
    adv = criar_advogado(client, token)

    sem_nome = post(client, '/api/escritorio/processos', {
        'advogado_id': adv, 'cliente_nome': '', 'cliente_telefone': '61988887777'
    }, token)
    assert sem_nome.status_code == 400

    sem_telefone = post(client, '/api/escritorio/processos', {
        'advogado_id': adv, 'cliente_nome': 'Cliente', 'cliente_telefone': ''
    }, token)
    assert sem_telefone.status_code == 400

    adv_invalido = post(client, '/api/escritorio/processos', {
        'advogado_id': 'x', 'cliente_nome': 'Cliente', 'cliente_telefone': '61988887777'
    }, token)
    assert adv_invalido.status_code == 400


def test_criar_processo_cliente_novo_e_login_cliente(client):
    token = registrar(client)['token']
    adv = criar_advogado(client, token)
    resp = criar_processo(client, token, adv)
    assert resp.status_code == 200, resp.get_json()
    dados = resp.get_json()
    assert dados['cliente_existente'] is False
    assert dados['senha_temporaria']
    assert dados['codigo_unico']
    assert dados['link_cliente_seguro'].startswith('/cliente/seguro/')

    login = post(client, '/api/cliente/login', {
        'telefone': '61988887777', 'senha': dados['senha_temporaria']
    })
    assert login.status_code == 200, login.get_json()


def test_cliente_existente_nao_gera_nova_senha(client):
    token = registrar(client)['token']
    adv = criar_advogado(client, token)

    primeiro = criar_processo(client, token, adv, telefone='61977773333')
    assert primeiro.status_code == 200
    assert primeiro.get_json()['senha_temporaria']

    segundo = criar_processo(client, token, adv, telefone='61977773333')
    assert segundo.status_code == 200
    dados = segundo.get_json()
    assert dados['cliente_existente'] is True
    assert dados['senha_temporaria'] is None
    assert 'senha existente' in dados['mensagem_acesso'].lower()


def test_edicao_processo_rejeita_advogado_de_outro_escritorio(client):
    token_a = registrar(client, 'a@teste.com')['token']
    token_b = registrar(client, 'b@teste.com')['token']
    adv_a = criar_advogado(client, token_a)
    adv_b = criar_advogado(client, token_b)
    processo = criar_processo(client, token_a, adv_a, telefone='61977774444').get_json()

    resp = put(client, f'/api/escritorio/processos/{processo["id"]}', {'advogado_id': adv_b}, token_a)
    assert resp.status_code == 404


def test_contato_seguro_e_link_publico(client):
    token = registrar(client)['token']
    adv = criar_advogado(client, token)
    processo = criar_processo(client, token, adv, telefone='61977775555').get_json()

    cca = post(client, '/api/escritorio/contato-seguro/iniciar', {
        'advogado_id': adv,
        'processo_id': processo['id'],
        'canal': 'whatsapp'
    }, token)
    assert cca.status_code == 200, cca.get_json()
    assert cca.get_json()['status'] == 'ativo'

    token_publico = processo['link_cliente_seguro'].rsplit('/', 1)[-1]
    publico = get(client, f'/api/cliente-publico/seguro/{token_publico}')
    assert publico.status_code == 200, publico.get_json()
    dados = publico.get_json()
    assert dados['valido'] is True
    assert dados['contato_ativo'] is True
    assert dados['advogado_nome'] == 'Dra. Teste'


def test_relatorio_pdf_processo(client):
    token = registrar(client)['token']
    adv = criar_advogado(client, token)
    processo = criar_processo(client, token, adv, telefone='61977776666').get_json()

    resp = get(client, f'/api/escritorio/relatorio/processo/{processo["id"]}/pdf', token)
    assert resp.status_code == 200
    assert resp.mimetype == 'application/pdf'
    assert resp.data.startswith(b'%PDF')


def test_reset_escritorio_dev_nao_expoe_conta_inexistente(client, monkeypatch):
    # No ambiente de testes IS_PRODUCTION é False. Sem SMTP, conta existente
    # recebe link_dev apenas para desenvolvimento; conta inexistente mantém
    # resposta genérica e não recebe link.
    registrar(client)
    monkeypatch.setattr(appmodule, 'SMTP_HOST', '')

    existe = post(client, '/api/escritorio/esqueci-senha', {'email': 'camada1@teste.com'})
    nao_existe = post(client, '/api/escritorio/esqueci-senha', {'email': 'naoexiste@teste.com'})

    assert existe.status_code == 200
    assert nao_existe.status_code == 200
    assert existe.get_json()['mensagem'] == nao_existe.get_json()['mensagem']
    assert existe.get_json().get('link_dev', '').startswith('/redefinir-senha?tipo=escritorio&token=')
    assert 'link_dev' not in nao_existe.get_json()


def test_reset_escritorio_producao_sem_smtp_falha_fechado(client, monkeypatch):
    monkeypatch.setattr(appmodule, 'IS_PRODUCTION', True)
    monkeypatch.setattr(appmodule, 'SMTP_HOST', '')
    resp = post(client, '/api/escritorio/esqueci-senha', {'email': 'qualquer@teste.com'})
    assert resp.status_code == 503
    assert 'temporariamente indisponível' in resp.get_json()['erro']
