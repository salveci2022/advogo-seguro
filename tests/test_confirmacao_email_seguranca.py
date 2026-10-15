# -*- coding: utf-8 -*-
"""A confirmação de e-mail nunca pode emitir sessão para conta já confirmada (F1)."""
import app as appmodule

SENHA = 'SenhaComercial123!'


def _registrar_e_confirmar(client, email, cnpj):
    registro = client.post('/api/comercial/registro', json={
        'nome': 'Escritório Confirmado',
        'cnpj': cnpj,
        'email': email,
        'senha': SENHA,
        'plano': 'escritorio',
    })
    assert registro.status_code == 201, registro.get_json()
    dados = registro.get_json()
    confirmacao = client.post('/api/comercial/confirmar-email', json={
        'email': email, 'codigo': dados['codigo_dev'],
    })
    assert confirmacao.status_code == 200, confirmacao.get_json()
    client.delete_cookie(appmodule.AUTH_COOKIE_NAME)
    client.delete_cookie(appmodule.CSRF_COOKIE_NAME)
    return dados


def _emitiu_cookie_auth(resposta):
    return any(
        cookie.startswith(appmodule.AUTH_COOKIE_NAME + '=')
        for cookie in resposta.headers.getlist('Set-Cookie')
    )


def test_confirmacao_repetida_com_codigo_qualquer_nao_cria_sessao(client):
    _registrar_e_confirmar(client, 'confirmado1@escritorio.com', '12.345.678/0001-95')

    resposta = client.post('/api/comercial/confirmar-email', json={
        'email': 'confirmado1@escritorio.com', 'codigo': '000000',
    })

    assert resposta.status_code == 400
    assert not _emitiu_cookie_auth(resposta)
    assert 'token' not in (resposta.get_json() or {})


def test_confirmacao_repetida_com_codigo_original_nao_cria_sessao(client):
    dados = _registrar_e_confirmar(client, 'confirmado2@escritorio.com', '11.222.333/0001-81')

    resposta = client.post('/api/comercial/confirmar-email', json={
        'email': 'confirmado2@escritorio.com', 'codigo': dados['codigo_dev'],
    })

    assert resposta.status_code == 400
    assert not _emitiu_cookie_auth(resposta)
    assert 'token' not in (resposta.get_json() or {})


def test_conta_confirmada_entra_somente_pelo_login_com_senha(client):
    _registrar_e_confirmar(client, 'confirmado3@escritorio.com', '45.723.174/0001-10')

    errado = client.post('/api/escritorio/login', json={
        'email': 'confirmado3@escritorio.com', 'senha': 'senha-errada-123',
    })
    certo = client.post('/api/escritorio/login', json={
        'email': 'confirmado3@escritorio.com', 'senha': SENHA,
    })

    assert errado.status_code == 401
    assert certo.status_code == 200
    assert _emitiu_cookie_auth(certo)
