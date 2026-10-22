# -*- coding: utf-8 -*-
"""APPSEC-007: o plano liberado vem do price.id efetivamente cobrado na assinatura Stripe.

metadata.plano é só contexto; preço desconhecido, ausente ou ambíguo não concede plano.
Nenhum teste acessa o Stripe real: construct_event, Session e Subscription são mocks.
"""
import logging
from types import SimpleNamespace

import pytest
import stripe

from conftest import appmodule

PRECOS = {
    'profissional': {'mensal': 'price_prof_oficial'},
    'escritorio': {'mensal': 'price_esc_oficial'},
    'blindagem': {'mensal': 'price_blind_oficial'},
}
PRECO = {plano: valores['mensal'] for plano, valores in PRECOS.items()}


@pytest.fixture(autouse=True)
def stripe_configurado(monkeypatch):
    monkeypatch.setattr(appmodule, 'STRIPE_SECRET_KEY', 'sk_test_mock')
    monkeypatch.setattr(appmodule, 'STRIPE_WEBHOOK_SECRET', 'whsec_mock')
    monkeypatch.setattr(appmodule, 'STRIPE_PRICE_MAP', PRECOS)
    monkeypatch.setattr(appmodule, 'PUBLIC_BASE_URL', 'https://advogo.example')

    def proibido(*args, **kwargs):
        raise AssertionError('chamada real ao Stripe')

    for alvo in (stripe.checkout.Session, stripe.Subscription, stripe.billing_portal.Session):
        for metodo in ('create', 'retrieve'):
            if hasattr(alvo, metodo):
                monkeypatch.setattr(alvo, metodo, proibido)


def criar_escritorio(client, email):
    resp = client.post('/api/escritorio/registro', json={'nome': f'Esc {email}', 'email': email, 'senha': 'SenhaSegura123'})
    assert resp.status_code == 200, resp.get_json()
    with appmodule.app.app_context():
        return appmodule.Escritorio.query.filter_by(email=email).one().id


def assinatura(escritorio_id, precos, status='active', plano_metadata=None, sub_id='sub_1'):
    metadata = {'escritorio_id': str(escritorio_id)}
    if plano_metadata:
        metadata['plano'] = plano_metadata
    return {'id': sub_id, 'customer': f'cus_{escritorio_id}', 'status': status, 'metadata': metadata,
            'items': {'data': [{'price': {'id': preco}} for preco in precos]}}


def enviar_evento(client, monkeypatch, objeto, tipo='customer.subscription.updated', event_id='evt_1'):
    evento = {'id': event_id, 'type': tipo, 'data': {'object': objeto}}
    monkeypatch.setattr(appmodule.stripe.Webhook, 'construct_event', lambda *a, **k: evento)
    return client.post('/webhook/stripe', data=b'{}', headers={'Stripe-Signature': 'assinado'})


def estado(escritorio_id):
    with appmodule.app.app_context():
        e = appmodule.db.session.get(appmodule.Escritorio, escritorio_id)
        return {'plano': appmodule.normalizar_codigo_plano(e.plano), 'ativo': e.plano_ativo(),
                'limite': e.limite_advogados(), 'status': e.assinatura_status}


# ---------- preço -> plano ----------

@pytest.mark.parametrize('plano', ['profissional', 'escritorio', 'blindagem'])
def test_preco_oficial_concede_o_plano_correspondente(client, monkeypatch, plano):
    eid = criar_escritorio(client, f'{plano}@x.com')
    resp = enviar_evento(client, monkeypatch, assinatura(eid, [PRECO[plano]], plano_metadata=plano))
    assert resp.status_code == 200, resp.get_json()
    assert estado(eid)['plano'] == plano and estado(eid)['ativo'] is True


def test_corporativo_nao_e_vendido_pelo_stripe(client, monkeypatch):
    with pytest.raises(RuntimeError):
        appmodule._carregar_mapa_stripe('{"corporativo": {"mensal": "price_corp"}}')
    eid = criar_escritorio(client, 'corp@x.com')
    enviar_evento(client, monkeypatch, assinatura(eid, ['price_corp'], plano_metadata='corporativo'))
    assert estado(eid) == {'plano': 'cancelado', 'ativo': False, 'limite': 0, 'status': 'active'}


def test_metadata_blindagem_com_preco_profissional_vale_o_preco(client, monkeypatch, caplog):
    caplog.set_level(logging.WARNING)
    eid = criar_escritorio(client, 'meta-alta@x.com')
    enviar_evento(client, monkeypatch, assinatura(eid, [PRECO['profissional']], plano_metadata='blindagem'))
    assert estado(eid)['plano'] == 'profissional' and estado(eid)['limite'] == 1
    assert 'plano_divergente' in caplog.text
    assert 'sk_test_mock' not in caplog.text and 'whsec_mock' not in caplog.text


def test_metadata_profissional_com_preco_blindagem_vale_o_preco(client, monkeypatch):
    eid = criar_escritorio(client, 'meta-baixa@x.com')
    enviar_evento(client, monkeypatch, assinatura(eid, [PRECO['blindagem']], plano_metadata='profissional'))
    assert estado(eid)['plano'] == 'blindagem' and estado(eid)['limite'] == 20


# ---------- falha fechada ----------

@pytest.mark.parametrize('objeto_itens', [
    {'data': [{'price': {'id': 'price_desconhecido'}}]},
    {'data': []},
    None,
    {'data': [{'price': None}]},
    {'data': [{'price': {'id': PRECO['profissional']}}, {'price': {'id': PRECO['blindagem']}}]},
    {'data': [{'price': {'id': PRECO['blindagem']}}, {'price': {'id': 'price_extra_desconhecido'}}]},
], ids=['desconhecido', 'sem_itens', 'items_ausente', 'price_nulo', 'planos_misturados', 'conhecido_mais_desconhecido'])
def test_preco_desconhecido_ausente_ou_ambiguo_nao_concede_plano(client, monkeypatch, caplog, objeto_itens):
    eid = criar_escritorio(client, 'falha@x.com')
    enviar_evento(client, monkeypatch, assinatura(eid, [PRECO['blindagem']], plano_metadata='blindagem'), event_id='evt_ok')
    assert estado(eid)['ativo'] is True

    objeto = assinatura(eid, [], plano_metadata='blindagem')
    objeto['items'] = objeto_itens
    resp = enviar_evento(client, monkeypatch, objeto, event_id='evt_ruim')
    assert resp.status_code == 200  # aceito para o Stripe não reenviar indefinidamente
    assert estado(eid)['ativo'] is False and estado(eid)['plano'] == 'cancelado'
    assert 'preco_nao_reconhecido' in caplog.text


# ---------- mudança de plano e status ----------

def test_downgrade_reflete_o_preco_novo(client, monkeypatch):
    eid = criar_escritorio(client, 'down@x.com')
    enviar_evento(client, monkeypatch, assinatura(eid, [PRECO['blindagem']], plano_metadata='blindagem'), event_id='evt_a')
    # Troca de preço pelo Customer Portal: a metadata continua "blindagem".
    enviar_evento(client, monkeypatch, assinatura(eid, [PRECO['profissional']], plano_metadata='blindagem'), event_id='evt_b')
    assert estado(eid)['plano'] == 'profissional' and estado(eid)['limite'] == 1


def test_upgrade_reflete_o_preco_novo(client, monkeypatch):
    eid = criar_escritorio(client, 'up@x.com')
    enviar_evento(client, monkeypatch, assinatura(eid, [PRECO['profissional']], plano_metadata='profissional'), event_id='evt_a')
    enviar_evento(client, monkeypatch, assinatura(eid, [PRECO['escritorio']], plano_metadata='profissional'), event_id='evt_b')
    assert estado(eid)['plano'] == 'escritorio' and estado(eid)['limite'] == 5


@pytest.mark.parametrize('status', ['canceled', 'unpaid', 'incomplete_expired', 'past_due', 'paused', 'incomplete'])
def test_assinatura_inativa_continua_sem_acesso(client, monkeypatch, status):
    eid = criar_escritorio(client, f'{status}@x.com')
    enviar_evento(client, monkeypatch, assinatura(eid, [PRECO['blindagem']]), event_id='evt_a')
    tipo = 'customer.subscription.deleted' if status == 'canceled' else 'customer.subscription.updated'
    enviar_evento(client, monkeypatch, assinatura(eid, [PRECO['blindagem']], status=status), tipo=tipo, event_id='evt_b')
    assert estado(eid)['ativo'] is False and estado(eid)['status'] == status


def test_webhook_repetido_continua_idempotente(client, monkeypatch):
    eid = criar_escritorio(client, 'idem@x.com')
    objeto = assinatura(eid, [PRECO['escritorio']])
    primeiro = enviar_evento(client, monkeypatch, objeto, event_id='evt_unico')
    segundo = enviar_evento(client, monkeypatch, assinatura(eid, ['price_desconhecido']), event_id='evt_unico')
    assert primeiro.get_json()['resultado'] == 'assinatura_active'
    assert segundo.get_json()['duplicado'] is True
    assert estado(eid)['plano'] == 'escritorio' and estado(eid)['ativo'] is True
    with appmodule.app.app_context():
        assert appmodule.EventoWebhook.query.filter_by(provedor='stripe', event_id='evt_unico').count() == 1


def test_invoice_paid_e_checkout_completed_tambem_usam_o_preco(client, monkeypatch):
    eid = criar_escritorio(client, 'fatura@x.com')
    sub = SimpleNamespace(**assinatura(eid, [PRECO['profissional']], plano_metadata='blindagem', sub_id='sub_fat'))
    monkeypatch.setattr(appmodule.stripe.Subscription, 'retrieve', lambda sub_id: sub)
    enviar_evento(client, monkeypatch, {'id': 'cs_1', 'client_reference_id': str(eid), 'customer': 'cus_x',
                                        'subscription': 'sub_fat'}, tipo='checkout.session.completed', event_id='evt_cs')
    assert estado(eid)['plano'] == 'profissional'
    sub.items = {'data': [{'price': {'id': PRECO['escritorio']}}]}
    enviar_evento(client, monkeypatch, {'id': 'in_1', 'subscription': 'sub_fat'}, tipo='invoice.paid', event_id='evt_in')
    assert estado(eid)['plano'] == 'escritorio'


def test_objeto_real_do_sdk_stripe_e_interpretado(client):
    eid = criar_escritorio(client, 'sdk@x.com')
    objeto = stripe.Subscription.construct_from(
        assinatura(eid, [PRECO['blindagem']], plano_metadata='profissional'), 'sk_test_mock')
    with appmodule.app.app_context():
        assert appmodule._plano_da_assinatura(objeto) == 'blindagem'


# ---------- checkout e propriedade ----------

def escritorio_confirmado(client, email, cnpj):
    cadastro = client.post('/api/comercial/registro', json={
        'nome': f'Esc {email}', 'email': email, 'senha': 'SenhaSegura123', 'tipo_pessoa': 'PJ',
        'cnpj': cnpj, 'plano': 'escritorio'})
    assert cadastro.status_code == 201, cadastro.get_json()
    confirma = client.post('/api/comercial/confirmar-email', json={'email': email, 'codigo': cadastro.get_json()['codigo_dev']})
    assert confirma.status_code == 200, confirma.get_json()
    with appmodule.app.app_context():
        eid = appmodule.Escritorio.query.filter_by(email=email).one().id
    return eid, {'Authorization': f"Bearer {confirma.get_json()['token']}"}


def test_checkout_usa_somente_precos_configurados_no_servidor(client, monkeypatch):
    _, headers = escritorio_confirmado(client, 'checkout@x.com', '11222333000181')
    capturado = {}

    def criar(**kwargs):
        capturado.update(kwargs)
        return SimpleNamespace(id='cs_srv', url='https://checkout.stripe.test/x')

    monkeypatch.setattr(appmodule.stripe.checkout.Session, 'create', criar)
    resp = client.post('/api/comercial/checkout', json={
        'plano': 'escritorio', 'price': 'price_do_atacante',
        'line_items': [{'price': 'price_do_atacante', 'quantity': 1}]}, headers=headers)
    assert resp.status_code == 200, resp.get_json()
    assert capturado['line_items'] == [{'price': PRECO['escritorio'], 'quantity': 1}]
    assert client.post('/api/comercial/checkout', json={'plano': 'corporativo'}, headers=headers).status_code == 400


def test_sincronizacao_usa_preco_e_escritorio_a_nao_ativa_plano_de_b(client, monkeypatch):
    eid_a, headers_a = escritorio_confirmado(client, 'a@x.com', '11222333000181')
    eid_b, _ = escritorio_confirmado(client, 'b@x.com', '11444777000161')
    with appmodule.app.app_context():
        for eid, sessao in ((eid_a, 'cs_a'), (eid_b, 'cs_b')):
            appmodule.db.session.get(appmodule.Escritorio, eid).stripe_checkout_session_id = sessao
        appmodule.db.session.commit()

    sessoes = {'cs_a': SimpleNamespace(id='cs_a', client_reference_id=str(eid_b), subscription='sub_b')}
    monkeypatch.setattr(appmodule.stripe.checkout.Session, 'retrieve', lambda sid: sessoes[sid])
    monkeypatch.setattr(appmodule.stripe.Subscription, 'retrieve',
                        lambda sid: SimpleNamespace(**assinatura(eid_b, [PRECO['blindagem']], sub_id=sid)))

    # A tenta sincronizar uma sessão que pertence a B, e uma sessão que não é a sua.
    assert client.post('/api/comercial/checkout/sincronizar', json={'session_id': 'cs_a'}, headers=headers_a).status_code == 403
    assert client.post('/api/comercial/checkout/sincronizar', json={'session_id': 'cs_b'}, headers=headers_a).status_code == 400
    assert estado(eid_b)['ativo'] is False and estado(eid_a)['ativo'] is False

    # Sessão legítima de A: metadata diz blindagem, preço cobrado é profissional.
    sessoes['cs_a'] = SimpleNamespace(id='cs_a', client_reference_id=str(eid_a), subscription='sub_a')
    monkeypatch.setattr(appmodule.stripe.Subscription, 'retrieve', lambda sid: SimpleNamespace(
        **assinatura(eid_a, [PRECO['profissional']], plano_metadata='blindagem', sub_id=sid)))
    resp = client.post('/api/comercial/checkout/sincronizar', json={'session_id': 'cs_a'}, headers=headers_a)
    assert resp.status_code == 200 and resp.get_json()['plano'] == 'profissional'
