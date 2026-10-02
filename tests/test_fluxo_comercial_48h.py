# -*- coding: utf-8 -*-
from datetime import timedelta, timezone
from types import SimpleNamespace

import app as appmodule


def _registro_comercial(client, email='novo@escritorio.com', cnpj='12.345.678/0001-95'):
    resposta = client.post('/api/comercial/registro', json={
        'nome': 'Novo Escritório',
        'cnpj': cnpj,
        'email': email,
        'senha': 'SenhaComercial123!',
        'plano': 'escritorio',
    })
    assert resposta.status_code == 201, resposta.get_json()
    return resposta.get_json()


def _confirmar(client, registro):
    resposta = client.post('/api/comercial/confirmar-email', json={
        'email': registro['email'],
        'codigo': registro['codigo_dev'],
    })
    assert resposta.status_code == 200, resposta.get_json()
    return resposta.get_json()


def test_registro_confirma_email_sem_liberar_plano_antes_do_checkout(client):
    registro = _registro_comercial(client)
    assert registro['confirmacao_email'] is True
    assert len(registro['codigo_dev']) == 6

    login_pendente = client.post('/api/escritorio/login', json={
        'email': registro['email'], 'senha': 'SenhaComercial123!'
    })
    assert login_pendente.status_code == 403
    assert login_pendente.get_json()['confirmacao_email'] is True

    confirmacao = _confirmar(client, registro)
    assert confirmacao['proximo'] == '/contratacao'
    token = confirmacao['token']
    status = client.get('/api/comercial/status', headers={'Authorization': f'Bearer {token}'})
    assert status.status_code == 200
    dados = status.get_json()
    assert dados['assinatura_status'] == 'aguardando_pagamento'
    assert dados['plano_ativo'] is False


def test_um_cnpj_nao_cria_duas_contas_comerciais(client):
    primeiro = _registro_comercial(client, 'primeiro@escritorio.com', '12.345.678/0001-95')
    _confirmar(client, primeiro)
    repetido = client.post('/api/comercial/registro', json={
        'nome': 'Outro Escritório',
        'cnpj': '12345678000195',
        'email': 'segundo@escritorio.com',
        'senha': 'SenhaComercial123!',
        'plano': 'profissional',
    })
    assert repetido.status_code == 409
    assert 'CNPJ' in repetido.get_json()['erro']


def test_checkout_cobra_somente_mensalidade_sem_periodo_gratuito(client, monkeypatch):
    registro = _registro_comercial(client)
    confirmacao = _confirmar(client, registro)
    token = confirmacao['token']
    headers = {'Authorization': f'Bearer {token}'}
    capturado = {}

    monkeypatch.setattr(appmodule, 'STRIPE_SECRET_KEY', 'sk_test_segura')
    monkeypatch.setattr(appmodule, 'STRIPE_PRICE_MAP', {
        'escritorio': {'mensal': 'price_mensal'}
    })
    monkeypatch.setattr(appmodule, 'PUBLIC_BASE_URL', 'https://advogo-seguro.example')

    def criar_sessao(**kwargs):
        capturado.update(kwargs)
        return SimpleNamespace(id='cs_test_123', url='https://checkout.stripe.test/cs_test_123')

    monkeypatch.setattr(appmodule.stripe.checkout.Session, 'create', criar_sessao)
    resposta = client.post('/api/comercial/checkout', json={'plano': 'escritorio'}, headers=headers)

    assert resposta.status_code == 200, resposta.get_json()
    assert resposta.get_json()['checkout_url'].startswith('https://checkout.stripe.test/')
    assert capturado['mode'] == 'subscription'
    assert capturado['payment_method_collection'] == 'always'
    assert capturado['line_items'] == [
        {'price': 'price_mensal', 'quantity': 1},
    ]
    assert capturado['subscription_data']['metadata']['plano'] == 'escritorio'
    assert 'trial_period_days' not in capturado['subscription_data']
    assert 'trial_settings' not in capturado['subscription_data']
    assert 'add_invoice_items' not in capturado['subscription_data']

def test_sincronizacao_ativa_plano_pago_sem_periodo_gratuito(client, monkeypatch):
    registro = _registro_comercial(client)
    confirmacao = _confirmar(client, registro)
    headers = {'Authorization': f"Bearer {confirmacao['token']}"}

    monkeypatch.setattr(appmodule, 'STRIPE_SECRET_KEY', 'sk_test_segura')
    monkeypatch.setattr(appmodule, 'STRIPE_PRICE_MAP', {
        'escritorio': {'mensal': 'price_mensal'}
    })
    monkeypatch.setattr(appmodule, 'PUBLIC_BASE_URL', 'https://advogo-seguro.example')
    monkeypatch.setattr(
        appmodule.stripe.checkout.Session, 'create',
        lambda **kwargs: SimpleNamespace(id='cs_test_pago', url='https://checkout.stripe.test/pago')
    )

    checkout = client.post('/api/comercial/checkout', json={'plano': 'escritorio'}, headers=headers)
    assert checkout.status_code == 200

    with appmodule.app.app_context():
        escritorio = appmodule.Escritorio.query.filter_by(email=registro['email']).first()
        escritorio_id = escritorio.id

    monkeypatch.setattr(
        appmodule.stripe.checkout.Session, 'retrieve',
        lambda session_id: SimpleNamespace(
            id=session_id,
            client_reference_id=str(escritorio_id),
            subscription='sub_paga',
            payment_status='paid',
        )
    )
    monkeypatch.setattr(
        appmodule.stripe.Subscription, 'retrieve',
        lambda subscription_id: SimpleNamespace(
            id=subscription_id,
            customer='cus_paga',
            status='active',
            metadata={'escritorio_id': str(escritorio_id), 'plano': 'escritorio'},
        )
    )

    sincronizacao = client.post(
        '/api/comercial/checkout/sincronizar',
        json={'session_id': 'cs_test_pago'},
        headers=headers,
    )

    assert sincronizacao.status_code == 200, sincronizacao.get_json()
    assert sincronizacao.get_json()['plano'] == 'escritorio'
    assert sincronizacao.get_json()['assinatura_status'] == 'active'

    with appmodule.app.app_context():
        escritorio = appmodule.Escritorio.query.filter_by(email=registro['email']).first()
        assert escritorio.assinatura_status == 'active'
        assert escritorio.plano == 'escritorio'
        assert escritorio.plano_ativo() is True
        assert escritorio.plano_expira is None
        assert escritorio.trial_utilizado_em is None
        assert escritorio.taxa_implantacao_paga_em is None

def test_texto_publico_nao_oferece_teste_gratuito_nem_data_fixa(client):
    for rota in ('/', '/planos', '/escritorio/cadastro', '/contratacao', '/contratacao/sucesso'):
        texto = client.get(rota).get_data(as_text=True)
        assert 'Teste gratuito' not in texto
        assert 'teste gratuito' not in texto
        assert 'Testar por 2 dias' not in texto
        assert 'teste por 2 dias' not in texto
        assert '16/08/2026' not in texto


def test_webhook_stripe_ativo_e_idempotente(client, monkeypatch):
    registro = _registro_comercial(client)
    _confirmar(client, registro)
    with appmodule.app.app_context():
        escritorio = appmodule.Escritorio.query.filter_by(email=registro['email']).first()
        escritorio_id = escritorio.id

    monkeypatch.setattr(appmodule, 'STRIPE_SECRET_KEY', 'sk_test_segura')
    monkeypatch.setattr(appmodule, 'STRIPE_WEBHOOK_SECRET', 'whsec_teste')
    evento = {
        'id': 'evt_assinatura_ativa',
        'type': 'customer.subscription.updated',
        'data': {'object': {
            'id': 'sub_ativa', 'customer': 'cus_ativa', 'status': 'active',
            'metadata': {'escritorio_id': str(escritorio_id), 'plano': 'escritorio'},
        }},
    }
    monkeypatch.setattr(appmodule.stripe.Webhook, 'construct_event', lambda *args, **kwargs: evento)

    primeiro = client.post('/webhook/stripe', data=b'{}', headers={'Stripe-Signature': 'assinatura'})
    segundo = client.post('/webhook/stripe', data=b'{}', headers={'Stripe-Signature': 'assinatura'})
    assert primeiro.status_code == 200, primeiro.get_json()
    assert primeiro.get_json()['resultado'] == 'assinatura_active'
    assert segundo.status_code == 200
    assert segundo.get_json()['duplicado'] is True

    with appmodule.app.app_context():
        escritorio = appmodule.Escritorio.query.filter_by(email=registro['email']).first()
        assert escritorio.plano == 'escritorio'
        assert escritorio.plano_ativo() is True
        assert appmodule.EventoWebhook.query.filter_by(
            provedor='stripe', event_id='evt_assinatura_ativa'
        ).count() == 1


def test_webhook_pagamento_recusado_bloqueia_sem_apagar_dados(client, monkeypatch):
    registro = _registro_comercial(client)
    _confirmar(client, registro)
    with appmodule.app.app_context():
        escritorio = appmodule.Escritorio.query.filter_by(email=registro['email']).first()
        escritorio.stripe_subscription_id = 'sub_recusada'
        escritorio.stripe_customer_id = 'cus_recusada'
        escritorio.plano_pretendido = 'escritorio'
        escritorio.plano = 'escritorio'
        escritorio.assinatura_status = 'active'
        appmodule.db.session.commit()
        escritorio_id = escritorio.id

    monkeypatch.setattr(appmodule, 'STRIPE_SECRET_KEY', 'sk_test_segura')
    monkeypatch.setattr(appmodule, 'STRIPE_WEBHOOK_SECRET', 'whsec_teste')
    monkeypatch.setattr(appmodule.stripe.Webhook, 'construct_event', lambda *args, **kwargs: {
        'id': 'evt_pagamento_recusado',
        'type': 'invoice.payment_failed',
        'data': {'object': {
            'id': 'in_recusada',
            'parent': {'subscription_details': {'subscription': 'sub_recusada'}},
        }},
    })
    resposta = client.post('/webhook/stripe', data=b'{}', headers={'Stripe-Signature': 'assinatura'})
    assert resposta.status_code == 200, resposta.get_json()
    assert resposta.get_json()['resultado'] == 'pagamento_pendente'

    with appmodule.app.app_context():
        escritorio = appmodule.db.session.get(appmodule.Escritorio, escritorio_id)
        assert escritorio.assinatura_status == 'past_due'
        assert escritorio.plano_ativo() is False
        assert escritorio.email == registro['email']
