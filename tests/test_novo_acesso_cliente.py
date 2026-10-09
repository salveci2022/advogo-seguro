# -*- coding: utf-8 -*-
"""Testes do botão "Gerar novo acesso" em /escritorio/clientes.

O botão reutiliza a rota existente POST /api/escritorio/cliente/<id>/link-reset
e o fluxo de redefinição POST /api/cliente/redefinir-senha.
"""
import hashlib
from datetime import timedelta

from conftest import appmodule

NOVA_SENHA = 'NovaSenhaCliente123'


def registrar(client, email):
    resp = client.post('/api/escritorio/registro', json={
        'nome': 'Escritorio Acesso', 'email': email, 'senha': 'SenhaSegura123'
    })
    assert resp.status_code == 200, resp.get_json()
    with appmodule.app.app_context():
        escritorio = appmodule.Escritorio.query.filter_by(email=email).first()
        escritorio.plano = 'profissional'
        escritorio.plano_expira = None
        appmodule.db.session.commit()
    return {'Authorization': f"Bearer {resp.get_json()['token']}"}


def criar_processo(client, headers, telefone):
    adv = client.post('/api/escritorio/advogados', json={
        'nome': 'Dra. Acesso', 'telefone_oficial': '61999990000'
    }, headers=headers)
    assert adv.status_code == 200, adv.get_json()
    proc = client.post('/api/escritorio/processos', json={
        'advogado_id': adv.get_json()['id'], 'cliente_nome': 'Cliente Acesso',
        'cliente_telefone': telefone
    }, headers=headers)
    assert proc.status_code == 200, proc.get_json()
    return proc.get_json()


def gerar_link(client, headers, cliente_id):
    return client.post(f'/api/escritorio/cliente/{cliente_id}/link-reset', headers=headers)


def token_do_link(link):
    return link.split('token=', 1)[1]


def test_pagina_clientes_exibe_botao_gerar_novo_acesso(client):
    html = client.get('/escritorio/clientes').get_data(as_text=True)
    assert 'Gerar novo acesso' in html
    assert '/link-reset' in html
    assert 'Novo link de acesso gerado com segurança' in html
    assert 'Envie este link ao cliente por um canal confiável.' in html
    assert 'Copiar link' in html


def test_escritorio_gera_link_para_cliente_proprio(client):
    headers = registrar(client, 'proprio@teste.com')
    proc = criar_processo(client, headers, '61977770001')

    resp = gerar_link(client, headers, proc['cliente_id'])
    assert resp.status_code == 200, resp.get_json()
    link = resp.get_json()['link']
    assert link.startswith('/redefinir-senha?tipo=cliente&token=')

    token = token_do_link(link)
    with appmodule.app.app_context():
        cliente = appmodule.db.session.get(appmodule.Cliente, proc['cliente_id'])
        # Apenas o hash do token é persistido.
        assert cliente.reset_token == hashlib.sha256(token.encode()).hexdigest()
        assert cliente.reset_token != token
        assert cliente.reset_token_expira > appmodule.agora_utc()


def test_impede_gerar_link_para_cliente_de_outro_escritorio(client):
    ha = registrar(client, 'dono@teste.com')
    proc = criar_processo(client, ha, '61977770002')
    hb = registrar(client, 'intruso@teste.com')

    resp = gerar_link(client, hb, proc['cliente_id'])
    assert resp.status_code == 404
    assert 'link' not in resp.get_json()
    with appmodule.app.app_context():
        cliente = appmodule.db.session.get(appmodule.Cliente, proc['cliente_id'])
        assert cliente.reset_token is None


def test_impede_gerar_link_para_cliente_compartilhado(client):
    ha = registrar(client, 'comp-a@teste.com')
    proc = criar_processo(client, ha, '61977770003')
    hb = registrar(client, 'comp-b@teste.com')
    criar_processo(client, hb, '61977770003')

    resp = gerar_link(client, ha, proc['cliente_id'])
    assert resp.status_code == 409
    assert 'link' not in resp.get_json()


def test_token_temporario_valido_redefine_senha(client):
    headers = registrar(client, 'valido@teste.com')
    proc = criar_processo(client, headers, '61977770004')
    token = token_do_link(gerar_link(client, headers, proc['cliente_id']).get_json()['link'])

    resp = client.post('/api/cliente/redefinir-senha', json={'token': token, 'nova_senha': NOVA_SENHA})
    assert resp.status_code == 200, resp.get_json()

    login = client.post('/api/cliente/login', json={'telefone': '61977770004', 'senha': NOVA_SENHA})
    assert login.status_code == 200, login.get_json()
    antiga = client.post('/api/cliente/login', json={
        'telefone': '61977770004', 'senha': proc['senha_temporaria']
    })
    assert antiga.status_code == 401


def test_token_expirado_recusado(client):
    headers = registrar(client, 'expirado@teste.com')
    proc = criar_processo(client, headers, '61977770005')
    token = token_do_link(gerar_link(client, headers, proc['cliente_id']).get_json()['link'])

    with appmodule.app.app_context():
        cliente = appmodule.db.session.get(appmodule.Cliente, proc['cliente_id'])
        cliente.reset_token_expira = appmodule.agora_utc() - timedelta(minutes=1)
        senha_hash_antes = cliente.senha_hash
        appmodule.db.session.commit()

    resp = client.post('/api/cliente/redefinir-senha', json={'token': token, 'nova_senha': NOVA_SENHA})
    assert resp.status_code == 400
    with appmodule.app.app_context():
        cliente = appmodule.db.session.get(appmodule.Cliente, proc['cliente_id'])
        assert cliente.senha_hash == senha_hash_antes


def test_token_usado_nao_pode_ser_reutilizado(client):
    headers = registrar(client, 'reuso@teste.com')
    proc = criar_processo(client, headers, '61977770006')
    token = token_do_link(gerar_link(client, headers, proc['cliente_id']).get_json()['link'])

    primeira = client.post('/api/cliente/redefinir-senha', json={'token': token, 'nova_senha': NOVA_SENHA})
    assert primeira.status_code == 200
    segunda = client.post('/api/cliente/redefinir-senha', json={'token': token, 'nova_senha': 'OutraSenhaQualquer99'})
    assert segunda.status_code == 400

    login = client.post('/api/cliente/login', json={'telefone': '61977770006', 'senha': NOVA_SENHA})
    assert login.status_code == 200


def test_novo_link_invalida_link_anterior(client):
    headers = registrar(client, 'rotacao@teste.com')
    proc = criar_processo(client, headers, '61977770007')
    token_antigo = token_do_link(gerar_link(client, headers, proc['cliente_id']).get_json()['link'])
    gerar_link(client, headers, proc['cliente_id'])

    resp = client.post('/api/cliente/redefinir-senha', json={'token': token_antigo, 'nova_senha': NOVA_SENHA})
    assert resp.status_code == 400


def test_senha_antiga_nao_exposta(client):
    headers = registrar(client, 'exposicao@teste.com')
    proc = criar_processo(client, headers, '61977770008')
    senha_antiga = proc['senha_temporaria']

    with appmodule.app.app_context():
        cliente = appmodule.db.session.get(appmodule.Cliente, proc['cliente_id'])
        senha_hash = cliente.senha_hash
        # Senha nunca armazenada em texto puro.
        assert senha_antiga not in senha_hash

    resp = gerar_link(client, headers, proc['cliente_id'])
    corpo = resp.get_data(as_text=True)
    assert set(resp.get_json().keys()) == {'link', 'cliente_nome'}
    assert senha_antiga not in corpo
    assert senha_hash not in corpo

    lista = client.get('/api/escritorio/clientes', headers=headers).get_data(as_text=True)
    assert senha_antiga not in lista
    assert senha_hash not in lista

    token = token_do_link(resp.get_json()['link'])
    client.post('/api/cliente/redefinir-senha', json={'token': token, 'nova_senha': NOVA_SENHA})
    with appmodule.app.app_context():
        cliente = appmodule.db.session.get(appmodule.Cliente, proc['cliente_id'])
        assert NOVA_SENHA not in cliente.senha_hash
        assert appmodule.verificar_senha(cliente.senha_hash, NOVA_SENHA)
