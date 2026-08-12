# -*- coding: utf-8 -*-
"""Testes de segurança — Camada 4 do ADVOGO SEGURO."""
import hashlib
import io

from conftest import appmodule


def registrar(client, email='seguranca@teste.com', senha='SenhaSegura123'):
    resp = client.post('/api/escritorio/registro', json={
        'nome': 'Escritorio Seguranca',
        'email': email,
        'senha': senha
    })
    assert resp.status_code == 200, resp.get_json()

    with appmodule.app.app_context():
        escritorio = appmodule.Escritorio.query.filter_by(email=email).first()
        assert escritorio is not None
        escritorio.plano = 'profissional'
        escritorio.plano_expira = None
        appmodule.db.session.commit()

    return resp

def bearer(resp):
    token = resp.get_json().get('token')
    assert token
    return {'Authorization': f'Bearer {token}'}


def criar_advogado(client, headers):
    resp = client.post('/api/escritorio/advogados', json={
        'nome': 'Dra. Segurança', 'telefone_oficial': '61999990000'
    }, headers=headers)
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()['id']


def test_sessao_browser_usa_cookie_httponly(client):
    resp = registrar(client)
    cookies = resp.headers.getlist('Set-Cookie')
    auth = next(c for c in cookies if c.startswith(appmodule.AUTH_COOKIE_NAME + '='))
    assert 'HttpOnly' in auth
    assert 'SameSite=Strict' in auth
    # Em ambiente de teste/local o token ainda é devolvido só para compatibilidade
    # com a suíte antiga; em produção ele é removido do JSON.


def test_producao_nao_devolve_jwt_no_json(client, monkeypatch):
    monkeypatch.setattr(appmodule, 'IS_PRODUCTION', True)
    resp = registrar(client, 'prod@teste.com')
    assert 'token' not in resp.get_json()
    cookies = resp.headers.getlist('Set-Cookie')
    assert any('HttpOnly' in c and 'Secure' in c for c in cookies)


def test_cookie_auth_get_funciona_e_post_exige_csrf(client):
    registrar(client)
    # O test_client guarda os cookies recebidos no registro.
    plano = client.get('/api/escritorio/plano')
    assert plano.status_code == 200, plano.get_json()

    sem_csrf = client.post('/api/escritorio/advogados', json={
        'nome': 'Dra. Cookie', 'telefone_oficial': '61999991111'
    })
    assert sem_csrf.status_code == 403

    csrf_cookie = client.get_cookie(appmodule.CSRF_COOKIE_NAME)
    assert csrf_cookie
    com_csrf = client.post('/api/escritorio/advogados', json={
        'nome': 'Dra. Cookie', 'telefone_oficial': '61999991111'
    }, headers={'X-CSRF-Token': csrf_cookie.value})
    assert com_csrf.status_code == 200, com_csrf.get_json()


def test_troca_senha_revoga_token_antigo(client):
    resp = registrar(client)
    headers = bearer(resp)
    troca = client.post('/api/escritorio/senha', json={
        'senha_atual': 'SenhaSegura123', 'nova_senha': 'OutraSenhaSegura456'
    }, headers=headers)
    assert troca.status_code == 200, troca.get_json()
    antigo = client.get('/api/escritorio/plano', headers=headers)
    assert antigo.status_code == 401


def test_senha_curta_rejeitada(client):
    resp = client.post('/api/escritorio/registro', json={
        'nome': 'Curta', 'email': 'curta@teste.com', 'senha': '123456789'
    })
    assert resp.status_code == 400


def test_reset_escritorio_armazena_hash_do_token(client, monkeypatch):
    registrar(client)
    monkeypatch.setattr(appmodule, 'SMTP_HOST', '')
    resp = client.post('/api/escritorio/esqueci-senha', json={'email': 'seguranca@teste.com'})
    assert resp.status_code == 200, resp.get_json()
    link = resp.get_json()['link_dev']
    token_bruto = link.split('token=', 1)[1]
    with appmodule.app.app_context():
        esc = appmodule.Escritorio.query.filter_by(email='seguranca@teste.com').first()
        assert esc.reset_token != token_bruto
        assert esc.reset_token == hashlib.sha256(token_bruto.encode()).hexdigest()


def test_link_reset_cliente_e_post_e_bloqueia_compartilhado(client):
    a = registrar(client, 'a-seg@teste.com')
    ha = bearer(a)
    adv_a = criar_advogado(client, ha)
    proc_a = client.post('/api/escritorio/processos', json={
        'advogado_id': adv_a, 'cliente_nome': 'Cliente Compartilhado',
        'cliente_telefone': '61988880001'
    }, headers=ha).get_json()

    b = registrar(client, 'b-seg@teste.com')
    hb = bearer(b)
    adv_b = criar_advogado(client, hb)
    client.post('/api/escritorio/processos', json={
        'advogado_id': adv_b, 'cliente_nome': 'Cliente Compartilhado',
        'cliente_telefone': '61988880001'
    }, headers=hb)

    get_antigo = client.get(f"/api/escritorio/cliente/{proc_a['cliente_id']}/link-reset", headers=ha)
    assert get_antigo.status_code == 405
    post_novo = client.post(f"/api/escritorio/cliente/{proc_a['cliente_id']}/link-reset", headers=ha)
    assert post_novo.status_code == 409


def test_cliente_compartilhado_nao_pode_ser_editado_por_um_escritorio(client):
    a = registrar(client, 'a2-seg@teste.com'); ha = bearer(a); adv_a = criar_advogado(client, ha)
    p = client.post('/api/escritorio/processos', json={
        'advogado_id': adv_a, 'cliente_nome': 'Compartilhado', 'cliente_telefone': '61988880002'
    }, headers=ha).get_json()
    b = registrar(client, 'b2-seg@teste.com'); hb = bearer(b); adv_b = criar_advogado(client, hb)
    client.post('/api/escritorio/processos', json={
        'advogado_id': adv_b, 'cliente_nome': 'Compartilhado', 'cliente_telefone': '61988880002'
    }, headers=hb)
    edit = client.put(f"/api/escritorio/clientes/{p['cliente_id']}", json={'nome': 'Alterado'}, headers=ha)
    assert edit.status_code == 409


def test_upload_rejeita_arquivo_falso_com_extensao_png(client):
    resp = registrar(client)
    headers = bearer(resp)
    adv = criar_advogado(client, headers)
    payload = {'foto': (io.BytesIO(b'<html>nao-e-imagem</html>'), 'foto.png')}
    up = client.post(f'/api/escritorio/advogados/{adv}/foto', data=payload, headers=headers, content_type='multipart/form-data')
    assert up.status_code == 400


def test_url_foto_rejeita_esquema_perigoso(client):
    resp = registrar(client)
    headers = bearer(resp)
    bad = client.post('/api/escritorio/advogados', json={
        'nome': 'Dra. URL', 'telefone_oficial': '61999992222',
        'foto_url': 'javascript:alert(1)'
    }, headers=headers)
    assert bad.status_code == 400


def test_webhook_sem_segredo_falha_fechado(client, monkeypatch):
    monkeypatch.setattr(appmodule, 'HOTMART_WEBHOOK_TOKEN', '')
    resp = client.post('/webhook/hotmart', json={'event': 'PURCHASE_APPROVED'})
    assert resp.status_code == 503


def test_webhook_exige_token_correto(client, monkeypatch):
    monkeypatch.setattr(appmodule, 'HOTMART_WEBHOOK_TOKEN', 'hottok-seguro')
    resp = client.post('/webhook/hotmart', json={'event': 'PURCHASE_APPROVED'}, headers={'X-Hotmart-Hottok': 'errado'})
    assert resp.status_code == 403


def test_admin_nao_usa_segredo_na_url(client, monkeypatch):
    monkeypatch.setattr(appmodule, 'ADMIN_SECRET', 'admin-seguro')
    antigo = client.get('/api/admin/listar-escritorios/admin-seguro')
    assert antigo.status_code == 404
    sem = client.get('/api/admin/escritorios')
    assert sem.status_code == 403
    com = client.get('/api/admin/escritorios', headers={'X-Admin-Secret': 'admin-seguro'})
    assert com.status_code == 200
    assert com.is_json


def test_headers_seguranca_presentes(client):
    resp = client.get('/')
    assert resp.headers.get('Content-Security-Policy')
    assert resp.headers.get('X-Frame-Options') == 'DENY'
    assert resp.headers.get('X-Content-Type-Options') == 'nosniff'
    assert resp.headers.get('Referrer-Policy') == 'no-referrer'
    assert resp.headers.get('Permissions-Policy')


def test_logout_limpa_cookie(client):
    registrar(client)
    csrf = client.get_cookie(appmodule.CSRF_COOKIE_NAME)
    resp = client.post('/api/logout', headers={'X-CSRF-Token': csrf.value})
    assert resp.status_code == 200
    cookies = resp.headers.getlist('Set-Cookie')
    assert any(appmodule.AUTH_COOKIE_NAME in c and 'Max-Age=0' in c for c in cookies)
