# -*- coding: utf-8 -*-
"""Cadastro de advogado Pessoa Física (CPF) e regras de CNPJ para Pessoa Jurídica."""
from types import SimpleNamespace

import app as appmodule

CPF_VALIDO = '529.982.247-25'
CPF_VALIDO_2 = '111.444.777-35'
CNPJ_VALIDO = '11.222.333/0001-81'
SENHA = 'SenhaComercial123!'


def _registrar(client, **campos):
    payload = {
        'nome': 'Maria da Silva',
        'email': 'maria@advogada.com',
        'senha': SENHA,
        'plano': 'profissional',
    }
    payload.update(campos)
    return client.post('/api/comercial/registro', json=payload)


def _registrar_pf(client, email='maria@advogada.com', cpf=CPF_VALIDO, plano='profissional'):
    return _registrar(client, email=email, tipo_pessoa='PF', cpf=cpf, plano=plano)


def _confirmar(client, registro):
    resposta = client.post('/api/comercial/confirmar-email', json={
        'email': registro['email'],
        'codigo': registro['codigo_dev'],
    })
    assert resposta.status_code == 200, resposta.get_json()
    return {'Authorization': f"Bearer {resposta.get_json()['token']}"}


def _escritorio(email):
    return appmodule.Escritorio.query.filter_by(email=email).first()


def _configurar_stripe(monkeypatch, capturado=None):
    monkeypatch.setattr(appmodule, 'STRIPE_SECRET_KEY', 'sk_test_segura')
    monkeypatch.setattr(appmodule, 'STRIPE_PRICE_MAP', {
        'profissional': {'mensal': 'price_profissional'},
        'escritorio': {'mensal': 'price_escritorio'},
    })
    monkeypatch.setattr(appmodule, 'PUBLIC_BASE_URL', 'https://advogo-seguro.example')

    def criar_sessao(**kwargs):
        if capturado is not None:
            capturado.update(kwargs)
        return SimpleNamespace(id='cs_test_pf', url='https://checkout.stripe.test/cs_test_pf')

    monkeypatch.setattr(appmodule.stripe.checkout.Session, 'create', criar_sessao)


# ── Pessoa Física ──────────────────────────────

def test_cadastro_pf_com_cpf_valido_armazena_somente_digitos(client):
    resposta = _registrar_pf(client)
    assert resposta.status_code == 201, resposta.get_json()
    dados = resposta.get_json()
    assert dados['tipo_pessoa'] == 'PF'
    assert dados['plano'] == 'profissional'

    with appmodule.app.app_context():
        escritorio = _escritorio('maria@advogada.com')
        assert escritorio.tipo_pessoa == 'PF'
        assert escritorio.cpf == '52998224725'
        assert escritorio.cnpj is None
        assert escritorio.eh_pessoa_fisica() is True
        assert escritorio.limite_advogados() == 1


def test_cadastro_pf_ignora_cnpj_enviado_junto(client):
    resposta = _registrar(client, tipo_pessoa='PF', cpf=CPF_VALIDO, cnpj=CNPJ_VALIDO)
    assert resposta.status_code == 201, resposta.get_json()
    with appmodule.app.app_context():
        assert _escritorio('maria@advogada.com').cnpj is None


def test_cadastro_pf_rejeita_cpf_invalido(client):
    for cpf in ('529.982.247-26', '111.111.111-11', '123', '', None):
        resposta = _registrar_pf(client, cpf=cpf)
        assert resposta.status_code == 400, cpf
        assert 'CPF' in resposta.get_json()['erro']
    with appmodule.app.app_context():
        assert appmodule.Escritorio.query.count() == 0


def test_cadastro_pf_rejeita_cpf_duplicado(client):
    primeiro = _registrar_pf(client).get_json()
    _confirmar(client, primeiro)

    repetido = _registrar_pf(client, email='outra@advogada.com', cpf='52998224725')
    assert repetido.status_code == 409
    assert 'CPF' in repetido.get_json()['erro']

    outro_cpf = _registrar_pf(client, email='outra@advogada.com', cpf=CPF_VALIDO_2)
    assert outro_cpf.status_code == 201, outro_cpf.get_json()


def test_tipo_pessoa_invalido_e_rejeitado(client):
    resposta = _registrar(client, tipo_pessoa='XX', cpf=CPF_VALIDO)
    assert resposta.status_code == 400


def test_pf_nao_pode_cadastrar_plano_empresarial(client):
    for plano in ('escritorio', 'blindagem', 'pro'):
        resposta = _registrar_pf(client, plano=plano)
        assert resposta.status_code == 400, plano
        assert 'Proteção Profissional' in resposta.get_json()['erro']


def test_pf_contrata_protecao_profissional_no_checkout(client, monkeypatch):
    headers = _confirmar(client, _registrar_pf(client).get_json())
    capturado = {}
    _configurar_stripe(monkeypatch, capturado)

    resposta = client.post('/api/comercial/checkout', json={'plano': 'profissional'}, headers=headers)
    assert resposta.status_code == 200, resposta.get_json()
    assert capturado['line_items'] == [{'price': 'price_profissional', 'quantity': 1}]
    assert capturado['subscription_data']['metadata']['plano'] == 'profissional'


def test_pf_nao_contrata_plano_empresarial_no_checkout(client, monkeypatch):
    headers = _confirmar(client, _registrar_pf(client).get_json())
    _configurar_stripe(monkeypatch)

    resposta = client.post('/api/comercial/checkout', json={'plano': 'escritorio'}, headers=headers)
    assert resposta.status_code == 400
    assert 'Proteção Profissional' in resposta.get_json()['erro']


def test_pf_checkout_bloqueia_cpf_ja_usado_em_outra_assinatura(client, monkeypatch):
    headers = _confirmar(client, _registrar_pf(client).get_json())
    with appmodule.app.app_context():
        appmodule.db.session.add(appmodule.Escritorio(
            nome='Conta anterior', email='anterior@advogada.com', senha_hash='x',
            tipo_pessoa='PF', cpf='52998224725', plano='profissional',
            assinatura_status='active',
        ))
        appmodule.db.session.commit()
    _configurar_stripe(monkeypatch)

    resposta = client.post('/api/comercial/checkout', json={'plano': 'profissional'}, headers=headers)
    assert resposta.status_code == 409
    assert 'CPF' in resposta.get_json()['erro']


def test_pf_mudanca_externa_no_stripe_nao_vira_plano_empresarial(client, monkeypatch):
    registro = _registrar_pf(client).get_json()
    _confirmar(client, registro)
    with appmodule.app.app_context():
        escritorio_id = _escritorio(registro['email']).id

    monkeypatch.setattr(appmodule, 'STRIPE_SECRET_KEY', 'sk_test_segura')
    monkeypatch.setattr(appmodule, 'STRIPE_WEBHOOK_SECRET', 'whsec_teste')
    monkeypatch.setattr(appmodule.stripe.Webhook, 'construct_event', lambda *a, **k: {
        'id': 'evt_pf_upgrade',
        'type': 'customer.subscription.updated',
        'data': {'object': {
            'id': 'sub_pf', 'customer': 'cus_pf', 'status': 'active',
            'metadata': {'escritorio_id': str(escritorio_id), 'plano': 'blindagem'},
        }},
    })
    resposta = client.post('/webhook/stripe', data=b'{}', headers={'Stripe-Signature': 'assinatura'})
    assert resposta.status_code == 200, resposta.get_json()

    with appmodule.app.app_context():
        escritorio = appmodule.db.session.get(appmodule.Escritorio, escritorio_id)
        assert escritorio.plano == 'profissional'
        assert escritorio.plano_ativo() is True
        assert escritorio.limite_advogados() == 1


def test_pf_nunca_ultrapassa_um_advogado_mesmo_com_plano_alterado(client):
    registro = _registrar_pf(client).get_json()
    headers = _confirmar(client, registro)
    with appmodule.app.app_context():
        escritorio = _escritorio(registro['email'])
        # Simula alteração externa (Hotmart/admin) para plano empresarial.
        escritorio.plano = 'corporativo'
        escritorio.plano_expira = None
        appmodule.db.session.commit()
        assert escritorio.config_plano()[0] == 'profissional'

    advogado = {'nome': 'Maria da Silva', 'oab': 'OAB/DF 1', 'telefone_oficial': '61999990000'}
    primeiro = client.post('/api/escritorio/advogados', json=advogado, headers=headers)
    assert primeiro.status_code == 200, primeiro.get_json()

    segundo = client.post('/api/escritorio/advogados', json={
        **advogado, 'nome': 'Outro Advogado', 'telefone_oficial': '61999990001'
    }, headers=headers)
    assert segundo.status_code == 403
    assert segundo.get_json()['limite_plano'] is True

    plano = client.get('/api/escritorio/plano', headers=headers).get_json()
    assert plano['limite_advogados'] == 1


def test_exportacao_lgpd_inclui_tipo_pessoa_e_cpf(client):
    headers = _confirmar(client, _registrar_pf(client).get_json())
    conta = client.get('/api/escritorio/privacidade/exportar', headers=headers).get_json()['conta']
    assert conta['tipo_pessoa'] == 'PF'
    assert conta['cpf'] == '52998224725'


# ── Pessoa Jurídica ────────────────────────────

def test_cadastro_pj_com_cnpj_valido_continua_funcionando(client):
    resposta = _registrar(client, nome='Silva Advocacia', email='contato@silva.com',
                          tipo_pessoa='PJ', cnpj=CNPJ_VALIDO, plano='escritorio')
    assert resposta.status_code == 201, resposta.get_json()
    assert resposta.get_json()['tipo_pessoa'] == 'PJ'
    with appmodule.app.app_context():
        escritorio = _escritorio('contato@silva.com')
        assert escritorio.tipo_pessoa == 'PJ'
        assert escritorio.cnpj == '11222333000181'
        assert escritorio.cpf is None


def test_cadastro_sem_tipo_pessoa_continua_sendo_pj(client):
    resposta = _registrar(client, email='contato@silva.com', cnpj=CNPJ_VALIDO, plano='blindagem')
    assert resposta.status_code == 201, resposta.get_json()
    assert resposta.get_json()['tipo_pessoa'] == 'PJ'


def test_cadastro_pj_rejeita_cnpj_invalido(client):
    for cnpj in ('11.222.333/0001-82', '00.000.000/0000-00', '1122233300018', '', None):
        resposta = _registrar(client, email='contato@silva.com', tipo_pessoa='PJ',
                              cnpj=cnpj, plano='escritorio')
        assert resposta.status_code == 400, cnpj
        assert 'CNPJ' in resposta.get_json()['erro']


def test_cadastro_pj_sem_cnpj_mesmo_informando_cpf_e_rejeitado(client):
    resposta = _registrar(client, email='contato@silva.com', tipo_pessoa='PJ',
                          cpf=CPF_VALIDO, plano='escritorio')
    assert resposta.status_code == 400
    assert 'CNPJ' in resposta.get_json()['erro']


def test_cadastro_pj_rejeita_cnpj_duplicado(client):
    primeiro = _registrar(client, email='contato@silva.com', tipo_pessoa='PJ',
                          cnpj=CNPJ_VALIDO, plano='escritorio').get_json()
    _confirmar(client, primeiro)
    repetido = _registrar(client, email='outro@silva.com', tipo_pessoa='PJ',
                          cnpj='11222333000181', plano='profissional')
    assert repetido.status_code == 409
    assert 'CNPJ' in repetido.get_json()['erro']


def test_checkout_pj_continua_funcionando(client, monkeypatch):
    headers = _confirmar(client, _registrar(
        client, email='contato@silva.com', tipo_pessoa='PJ', cnpj=CNPJ_VALIDO, plano='escritorio'
    ).get_json())
    capturado = {}
    _configurar_stripe(monkeypatch, capturado)

    resposta = client.post('/api/comercial/checkout', json={'plano': 'escritorio'}, headers=headers)
    assert resposta.status_code == 200, resposta.get_json()
    assert capturado['line_items'] == [{'price': 'price_escritorio', 'quantity': 1}]
    assert capturado['subscription_data']['metadata']['plano'] == 'escritorio'


# ── Compatibilidade com registros antigos ──────

def test_registro_antigo_sem_tipo_pessoa_e_tratado_como_pj(client, monkeypatch):
    with appmodule.app.app_context():
        # Registro legado: sem tipo_pessoa, CNPJ formatado e com dígito
        # verificador que a nova validação recusaria em cadastros novos.
        appmodule.db.session.add(appmodule.Escritorio(
            nome='Escritório Antigo', email='antigo@escritorio.com',
            senha_hash=appmodule.hash_senha(SENHA), cnpj='12.345.678/0001-00',
            plano='trial', plano_expira=appmodule.agora_utc(),
        ))
        appmodule.db.session.commit()
        legado = _escritorio('antigo@escritorio.com')
        assert legado.tipo_pessoa is None
        assert legado.cpf is None
        assert legado.eh_pessoa_fisica() is False
        legado.plano = 'pro'
        legado.plano_expira = None
        appmodule.db.session.commit()
        assert legado.config_plano()[0] == 'escritorio'
        assert legado.limite_advogados() == 5
        legado.plano = 'trial'
        legado.plano_expira = appmodule.agora_utc()
        appmodule.db.session.commit()

    login = client.post('/api/escritorio/login', json={'email': 'antigo@escritorio.com', 'senha': SENHA})
    assert login.status_code == 200, login.get_json()
    headers = {'Authorization': f"Bearer {login.get_json()['token']}"}

    _configurar_stripe(monkeypatch)
    checkout = client.post('/api/comercial/checkout', json={'plano': 'escritorio'}, headers=headers)
    assert checkout.status_code == 200, checkout.get_json()

    conta = client.get('/api/escritorio/privacidade/exportar', headers=headers).get_json()['conta']
    assert conta['tipo_pessoa'] == 'PJ'
    assert conta['cnpj'] == '12.345.678/0001-00'


def test_validadores_de_documento():
    assert appmodule._cpf_valido('52998224725')
    assert appmodule._cpf_valido('11144477735')
    assert not appmodule._cpf_valido('52998224724')
    assert not appmodule._cpf_valido('00000000000')
    assert appmodule._cnpj_valido('11222333000181')
    assert appmodule._cnpj_valido('12345678000195')
    assert not appmodule._cnpj_valido('11222333000180')
    assert not appmodule._cnpj_valido('11111111111111')


def test_tela_de_cadastro_oferece_pf_e_pj(client):
    html = client.get('/escritorio/cadastro').get_data(as_text=True)
    assert 'Pessoa Física — Advogado' in html
    assert 'Pessoa Jurídica — Escritório' in html
    assert 'id="cpf"' in html
    assert 'id="cnpj"' in html
