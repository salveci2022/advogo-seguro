# -*- coding: utf-8 -*-
"""Testes de bugs e estabilidade — Camada 2 da auditoria ADVOGO SEGURO.

Todos usam SQLite em memória pelo fixture tests/conftest.py.
"""
import io

from conftest import appmodule


def post(client, path, body=None, token=None, **kwargs):
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    if 'data' in kwargs:
        return client.post(path, headers=headers, **kwargs)
    return client.post(path, json=body or {}, headers=headers, **kwargs)


def get(client, path, token=None):
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    return client.get(path, headers=headers)


def put(client, path, body=None, token=None):
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    return client.put(path, json=body or {}, headers=headers)


def registrar(client, email='estabilidade@teste.com'):
    resp = post(client, '/api/escritorio/registro', {
        'nome': 'Escritório Estabilidade',
        'email': email,
        'senha': 'SenhaTeste123',
    })
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()['token']


def criar_advogado(client, token):
    resp = post(client, '/api/escritorio/advogados', {
        'nome': 'Dra. Estabilidade',
        'telefone_oficial': '61999990000',
        'oab': 'OAB/DF 12345',
    }, token)
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()['id']


def criar_processo(client, token, advogado_id):
    resp = post(client, '/api/escritorio/processos', {
        'advogado_id': advogado_id,
        'cliente_nome': 'Cliente Estabilidade',
        'cliente_telefone': '61988887777',
        'cliente_email': 'cliente.estabilidade@teste.com',
        'numero_processo': '0000000-00.2026.0.00.0000',
        'descricao': 'Teste Camada 2',
    }, token)
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()


def test_token_invalido_retorna_401_sem_500(client):
    resp = get(client, '/api/escritorio/plano', 'token.invalido')
    assert resp.status_code == 401
    assert resp.is_json


def test_404_e_405_retornam_json_controlado(client):
    inexistente = get(client, '/rota-que-nao-existe-camada2')
    assert inexistente.status_code == 404
    assert inexistente.is_json
    assert 'erro' in inexistente.get_json()

    metodo = get(client, '/api/escritorio/login')
    assert metodo.status_code == 405
    assert metodo.is_json
    assert 'erro' in metodo.get_json()


def test_json_malformado_retorna_400_sem_500(client):
    resp = client.post(
        '/api/escritorio/registro',
        data='{',
        content_type='application/json',
    )
    assert resp.status_code == 400
    assert resp.is_json


def test_rate_limit_bloqueia_na_sexta_tentativa(client):
    appmodule._tentativas_login.clear()
    for _ in range(appmodule.MAX_TENTATIVAS):
        resp = post(client, '/api/escritorio/login', {
            'email': 'naoexiste-rate@teste.com',
            'senha': 'errada',
        })
        assert resp.status_code == 401

    bloqueada = post(client, '/api/escritorio/login', {
        'email': 'naoexiste-rate@teste.com',
        'senha': 'errada',
    })
    assert bloqueada.status_code == 429


def test_rate_limit_limpa_chaves_expiradas(client):
    appmodule._tentativas_login.clear()
    antigo = appmodule.agora_utc().timestamp() - appmodule.JANELA_BLOQUEIO_SEGUNDOS - 10
    for i in range(1001):
        appmodule._tentativas_login[f'ip:stale-{i}@teste.com'] = [antigo]

    resp = post(client, '/api/escritorio/login', {
        'email': 'gatilho@teste.com',
        'senha': 'errada',
    })
    assert resp.status_code == 401
    assert len(appmodule._tentativas_login) < 20


def test_edicao_advogado_com_null_retorna_400(client):
    token = registrar(client)
    advogado_id = criar_advogado(client, token)
    resp = put(client, f'/api/escritorio/advogados/{advogado_id}', {'nome': None}, token)
    assert resp.status_code == 400
    assert resp.is_json


def test_edicao_processo_com_null_nao_gera_500(client):
    token = registrar(client)
    advogado_id = criar_advogado(client, token)
    processo = criar_processo(client, token, advogado_id)

    resp = put(client, f'/api/escritorio/processos/{processo["id"]}', {
        'numero_processo': None,
        'descricao': None,
    }, token)
    assert resp.status_code == 200, resp.get_json()


def test_edicao_cliente_com_null_retorna_400(client):
    token = registrar(client)
    advogado_id = criar_advogado(client, token)
    processo = criar_processo(client, token, advogado_id)

    resp = put(client, f'/api/escritorio/clientes/{processo["cliente_id"]}', {'nome': None}, token)
    assert resp.status_code == 400
    assert resp.is_json


def test_registro_campos_ausentes_retorna_400(client):
    resp = post(client, '/api/escritorio/registro', {})
    assert resp.status_code == 400
    assert resp.is_json


def test_id_inexistente_retorna_404(client):
    token = registrar(client)
    resp = put(client, '/api/escritorio/advogados/999999', {'nome': 'Teste'}, token)
    assert resp.status_code == 404
    assert resp.is_json


def test_upload_acima_do_limite_retorna_413_controlado(client):
    token = registrar(client)
    advogado_id = criar_advogado(client, token)
    headers = {'Authorization': f'Bearer {token}'}
    payload = {
        'foto': (io.BytesIO(b'x' * (appmodule.UPLOAD_TAMANHO_MAXIMO_BYTES + 1024)), 'grande.jpg')
    }
    resp = client.post(
        f'/api/escritorio/advogados/{advogado_id}/foto',
        data=payload,
        headers=headers,
        content_type='multipart/form-data',
    )
    assert resp.status_code == 413
    assert resp.is_json


def test_campos_null_em_registro_e_login_nao_geram_500(client):
    registro = post(client, '/api/escritorio/registro', {
        'nome': None, 'email': None, 'senha': None, 'cnpj': None
    })
    assert registro.status_code == 400
    assert registro.is_json

    login = post(client, '/api/escritorio/login', {'email': None, 'senha': None})
    assert login.status_code in (401, 429)
    assert login.is_json


def test_campos_null_em_processo_nao_geram_500(client):
    token = registrar(client)
    advogado_id = criar_advogado(client, token)
    resp = post(client, '/api/escritorio/processos', {
        'advogado_id': advogado_id,
        'cliente_nome': None,
        'cliente_telefone': None,
        'cliente_email': None,
        'numero_processo': None,
        'descricao': None,
    }, token)
    assert resp.status_code == 400
    assert resp.is_json


def test_webhook_payload_parcial_nao_gera_500(client, monkeypatch):
    monkeypatch.setattr(appmodule, 'HOTMART_WEBHOOK_TOKEN', 'token-teste')
    resp = client.post(
        '/webhook/hotmart',
        json={'event': 'PURCHASE_APPROVED', 'data': None},
        headers={'X-Hotmart-Hottok': 'token-teste'}
    )
    assert resp.status_code == 400
    assert resp.is_json
