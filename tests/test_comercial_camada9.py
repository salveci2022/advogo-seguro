# -*- coding: utf-8 -*-
"""Camada 9 — coerência comercial, planos e cobrança."""
from datetime import timedelta

import app as appmodule

db = appmodule.db
Escritorio = appmodule.Escritorio
EventoWebhook = appmodule.EventoWebhook


def registrar(client, email='comercial@teste.com'):
    resp = client.post('/api/escritorio/registro', json={
        'nome': 'Escritório Comercial',
        'email': email,
        'senha': 'SenhaComercial123!',
    })
    assert resp.status_code == 200, resp.get_json()
    token = resp.get_json()['token']
    return {'Authorization': f'Bearer {token}'}


def test_catalogo_precos_limites_e_implantacao():
    p = appmodule.PLANOS_ADVOGO_SEGURO
    assert p['profissional'] == {
        'nome': 'Proteção Profissional',
        'preco_mensal': 179.00,
        'implantacao': 297.00,
        'limite_advogados': 1,
    }
    assert p['escritorio']['preco_mensal'] == 497.00
    assert p['escritorio']['implantacao'] == 697.00
    assert p['escritorio']['limite_advogados'] == 5
    assert p['blindagem']['preco_mensal'] == 997.00
    assert p['blindagem']['implantacao'] == 1497.00
    assert p['blindagem']['limite_advogados'] == 20
    assert p['corporativo']['preco_mensal'] == 1597.00
    assert p['corporativo']['implantacao'] is None
    assert p['corporativo']['limite_advogados'] is None


def test_pagina_e_api_planos_usam_fonte_unica_sem_placeholder(client):
    api = client.get('/api/publico/planos')
    assert api.status_code == 200
    dados = api.get_json()
    assert dados['trial_dias'] == 0
    assert dados['trial_limite_advogados'] == 1
    assert [p['preco_mensal'] for p in dados['planos']] == [179.0, 497.0, 997.0, 1597.0]

    html = client.get('/planos')
    assert html.status_code == 200
    texto = html.get_data(as_text=True)
    for valor in ('179', '497', '997', '1.597'):
        assert valor in texto
    assert 'Substitua este texto' not in texto
    assert 'Controle de usuários e permissões' not in texto
    assert 'MAIS CONTRATADO' not in texto


def test_home_sidebar_e_url_antiga_apontam_para_planos(client):
    home = client.get('/').get_data(as_text=True)
    sidebar = client.get('/escritorio/dashboard').get_data(as_text=True)
    antigo = client.get('/static/planos.html').get_data(as_text=True)
    assert 'href="/planos"' in home
    assert 'href="/planos"' in sidebar
    assert 'url=/planos' in antigo


def test_cadastro_comercial_nasce_inativo_sem_trial_gratuito(client):
    headers = registrar(client, 'trial-comercial@teste.com')
    plano = client.get('/api/escritorio/plano', headers=headers)
    assert plano.status_code == 200
    dados = plano.get_json()
    assert dados['codigo'] == 'trial'
    assert dados['limite_advogados'] == 1
    assert dados['plano_ativo'] is False
    with appmodule.app.app_context():
        e = Escritorio.query.filter_by(email='trial-comercial@teste.com').first()
        assert e.plano_expira is not None
        assert e.plano_expira <= appmodule.agora_utc()


def test_cancelado_nao_aparece_como_trial(client):
    headers = registrar(client, 'cancelado@teste.com')
    with appmodule.app.app_context():
        e = Escritorio.query.filter_by(email='cancelado@teste.com').first()
        e.plano = 'cancelado'
        e.plano_expira = appmodule.agora_utc()
        db.session.commit()

    resp = client.get('/api/escritorio/plano', headers=headers)
    assert resp.status_code == 200
    dados = resp.get_json()
    assert dados['codigo'] == 'cancelado'
    assert dados['nome'] == 'Plano Inativo'
    assert dados['plano_ativo'] is False
    assert dados['pode_adicionar_advogado'] is False


def test_hotmart_produto_nao_mapeado_nunca_ativa(client, monkeypatch):
    registrar(client, 'buyer-desconhecido@teste.com')
    monkeypatch.setattr(appmodule, 'HOTMART_WEBHOOK_TOKEN', 'hottok-teste')
    monkeypatch.setattr(appmodule, 'HOTMART_PLAN_MAP', {})

    resp = client.post('/webhook/hotmart', json={
        'id': 'evt-desconhecido-1',
        'event': 'PURCHASE_APPROVED',
        'data': {
            'buyer': {'email': 'buyer-desconhecido@teste.com'},
            'product': {'id': 999999},
        }
    }, headers={'X-Hotmart-Hottok': 'hottok-teste'})
    assert resp.status_code == 202
    assert resp.get_json()['motivo'] == 'produto_nao_mapeado'

    with appmodule.app.app_context():
        e = Escritorio.query.filter_by(email='buyer-desconhecido@teste.com').first()
        assert e.plano == 'trial'


def test_hotmart_mapeado_ativa_plano_correto_e_e_idempotente(client, monkeypatch):
    registrar(client, 'buyer-blindagem@teste.com')
    monkeypatch.setattr(appmodule, 'HOTMART_WEBHOOK_TOKEN', 'hottok-teste')
    monkeypatch.setattr(appmodule, 'HOTMART_PLAN_MAP', {'321': 'blindagem'})

    payload = {
        'id': 'evt-blindagem-1',
        'event': 'PURCHASE_APPROVED',
        'data': {
            'buyer': {'email': 'buyer-blindagem@teste.com'},
            'product': {'id': 321},
        }
    }
    r1 = client.post('/webhook/hotmart', json=payload,
                     headers={'X-Hotmart-Hottok': 'hottok-teste'})
    assert r1.status_code == 200
    assert r1.get_json()['plano'] == 'blindagem'

    with appmodule.app.app_context():
        e = Escritorio.query.filter_by(email='buyer-blindagem@teste.com').first()
        primeira_expiracao = e.plano_expira
        assert e.plano == 'blindagem'
        assert EventoWebhook.query.count() == 1

    r2 = client.post('/webhook/hotmart', json=payload,
                     headers={'X-Hotmart-Hottok': 'hottok-teste'})
    assert r2.status_code == 200
    assert r2.get_json()['duplicado'] is True

    with appmodule.app.app_context():
        e = Escritorio.query.filter_by(email='buyer-blindagem@teste.com').first()
        assert e.plano_expira == primeira_expiracao
        assert EventoWebhook.query.count() == 1


def test_cancelamento_antigo_nao_derruba_plano_diferente_e_admin_legado_canonicaliza(client, monkeypatch):
    registrar(client, 'buyer-multi@teste.com')
    monkeypatch.setattr(appmodule, 'HOTMART_WEBHOOK_TOKEN', 'hottok-teste')
    monkeypatch.setattr(appmodule, 'HOTMART_PLAN_MAP', {'100': 'profissional'})
    monkeypatch.setattr(appmodule, 'ADMIN_SECRET', 'admin-comercial')

    with appmodule.app.app_context():
        e = Escritorio.query.filter_by(email='buyer-multi@teste.com').first()
        e.plano = 'blindagem'
        e.plano_expira = appmodule.agora_utc() + timedelta(days=30)
        db.session.commit()

    cancel = client.post('/webhook/hotmart', json={
        'id': 'evt-cancel-antigo',
        'event': 'PURCHASE_REFUNDED',
        'data': {
            'buyer': {'email': 'buyer-multi@teste.com'},
            'product': {'id': 100},
        }
    }, headers={'X-Hotmart-Hottok': 'hottok-teste'})
    assert cancel.status_code == 200
    assert cancel.get_json()['resultado'] == 'cancelamento_ignorado_plano_diferente'

    with appmodule.app.app_context():
        e = Escritorio.query.filter_by(email='buyer-multi@teste.com').first()
        assert e.plano == 'blindagem'

    legado = client.post('/api/admin/ativar-pro', json={
        'email': 'buyer-multi@teste.com'
    }, headers={'X-Admin-Secret': 'admin-comercial'})
    assert legado.status_code == 200
    assert legado.get_json()['plano'] == 'escritorio'

    with appmodule.app.app_context():
        e = Escritorio.query.filter_by(email='buyer-multi@teste.com').first()
        assert e.plano == 'escritorio'
