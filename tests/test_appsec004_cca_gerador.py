# -*- coding: utf-8 -*-
"""APPSEC-004: a geração do CCA nunca entra em loop, não esgota e não devolve 500 em colisão.

Formato novo CCA-XXXX-XXXX (alfabeto sem 0 O 1 I L); registros antigos CCA-NNNN continuam válidos.
"""
import inspect
import re
from datetime import timedelta

import pytest

from conftest import appmodule

ALFABETO = appmodule.CCA_ALFABETO
FORMATO = re.compile(r'^CCA-[' + ALFABETO + r']{4}-[' + ALFABETO + r']{4}$')
TELEFONE = '61977776666'


def registrar(client, email):
    resp = client.post('/api/escritorio/registro', json={
        'nome': f'Escritorio {email}', 'email': email, 'senha': 'SenhaSegura123'
    })
    assert resp.status_code == 200, resp.get_json()
    with appmodule.app.app_context():
        escritorio = appmodule.Escritorio.query.filter_by(email=email).first()
        escritorio.plano = 'profissional'
        escritorio.plano_expira = None
        appmodule.db.session.commit()
    return {'Authorization': f"Bearer {resp.get_json()['token']}"}


def montar_escritorio(client, email, telefone_cliente):
    he = registrar(client, email)
    adv = client.post('/api/escritorio/advogados', json={
        'nome': 'Dra. CCA', 'telefone_oficial': '61911113333'
    }, headers=he).get_json()['id']
    proc = client.post('/api/escritorio/processos', json={
        'advogado_id': adv, 'cliente_nome': 'Cliente CCA', 'cliente_telefone': telefone_cliente
    }, headers=he).get_json()
    return {'he': he, 'adv': adv, 'proc': proc}


@pytest.fixture()
def cenario(client):
    return montar_escritorio(client, 'cca@escritorio-a.com', TELEFONE)


def iniciar(client, c):
    return client.post('/api/escritorio/contato-seguro/iniciar', json={
        'advogado_id': c['adv'], 'processo_id': c['proc']['id'], 'canal': 'whatsapp'
    }, headers=c['he'])


def headers_cliente(client, c):
    login = client.post('/api/cliente/login', json={
        'telefone': TELEFONE, 'senha': c['proc']['senha_temporaria']
    })
    return {'Authorization': f"Bearer {login.get_json()['token']}"}


def contatos():
    with appmodule.app.app_context():
        return [(c.codigo_cca, c.status) for c in appmodule.ContatoSeguro.query.order_by(appmodule.ContatoSeguro.id)]


# ---------- formato e entropia ----------

def test_formato_novo_e_alfabeto_sem_caracteres_ambiguos():
    codigos = [appmodule.gerar_codigo_cca() for _ in range(2000)]
    assert all(FORMATO.match(c) for c in codigos)
    assert all(len(c) <= 20 for c in codigos)  # cabe no VARCHAR(20) atual
    assert not set('0O1IL') & set(ALFABETO)
    assert len(ALFABETO) == 31 and appmodule.CCA_TAMANHO == 8  # 31^8 ≈ 8,5 x 10^11
    usados = set(''.join(c[4:].replace('-', '') for c in codigos))
    assert usados == set(ALFABETO)
    assert len(set(codigos)) == len(codigos)


def test_gerador_usa_secrets_e_nao_tem_loop_ilimitado():
    fonte = inspect.getsource(appmodule.gerar_codigo_cca) + inspect.getsource(appmodule._salvar_novo_cca)
    assert 'secrets.choice' in fonte
    assert 'while True' not in fonte
    assert 'range(CCA_MAX_TENTATIVAS)' in fonte


# ---------- fluxo normal ----------

def test_geracao_normal(client, cenario):
    resp = iniciar(client, cenario)
    assert resp.status_code == 200
    dados = resp.get_json()
    assert FORMATO.match(dados['codigo_cca'])
    assert dados['status'] == 'ativo'


def test_varias_geracoes_consecutivas(client, cenario):
    codigos = []
    for _ in range(25):
        resp = iniciar(client, cenario)
        assert resp.status_code == 200
        codigos.append(resp.get_json()['codigo_cca'])
    assert len(set(codigos)) == 25
    estados = [s for _, s in contatos()]
    assert estados.count('ativo') == 1 and estados.count('cancelado') == 24


def test_codigo_expirado(client, cenario):
    codigo = iniciar(client, cenario).get_json()['codigo_cca']
    with appmodule.app.app_context():
        cca = appmodule.ContatoSeguro.query.filter_by(codigo_cca=codigo).one()
        cca.expira_em = appmodule.agora_utc() - timedelta(minutes=1)
        appmodule.db.session.commit()
    lista = client.get('/api/escritorio/contato-seguro/listar', headers=cenario['he']).get_json()
    assert lista[0]['status'] == 'expirado'
    hc = headers_cliente(client, cenario)
    assert client.get('/api/cliente/contato-seguro/ativo', headers=hc).get_json() == {'ativo': False}
    assert iniciar(client, cenario).status_code == 200


def test_codigo_cancelado(client, cenario):
    dados = iniciar(client, cenario).get_json()
    assert client.post(f"/api/escritorio/contato-seguro/cancelar/{dados['id']}", headers=cenario['he']).status_code == 200
    hc = headers_cliente(client, cenario)
    assert client.get('/api/cliente/contato-seguro/ativo', headers=hc).get_json() == {'ativo': False}


def test_reinicio_gera_codigo_novo_e_cancela_o_anterior(client, cenario):
    antigo = iniciar(client, cenario).get_json()
    resp = client.post(f"/api/escritorio/contato-seguro/reiniciar/{antigo['id']}", headers=cenario['he'])
    assert resp.status_code == 200
    novo = resp.get_json()
    assert FORMATO.match(novo['codigo_cca']) and novo['codigo_cca'] != antigo['codigo_cca']
    assert contatos() == [(antigo['codigo_cca'], 'cancelado'), (novo['codigo_cca'], 'ativo')]


# ---------- colisão, limite e ausência de loop ----------

def test_colisao_detectada_antes_do_insert_gera_outro_codigo(client, cenario, monkeypatch):
    existente = iniciar(client, cenario).get_json()['codigo_cca']
    sequencia = iter([existente, existente, 'CCA-AAAA-BBBB'])
    monkeypatch.setattr(appmodule, 'gerar_codigo_cca', lambda: next(sequencia))
    resp = iniciar(client, cenario)
    assert resp.status_code == 200
    assert resp.get_json()['codigo_cca'] == 'CCA-AAAA-BBBB'


def test_colisao_no_insert_concorrente_faz_rollback_e_nova_tentativa(client, cenario, monkeypatch):
    """Simula a corrida: a checagem não vê o código, mas outra requisição já o gravou."""
    primeiro = iniciar(client, cenario).get_json()
    sequencia = iter([primeiro['codigo_cca'], 'CCA-CCCC-DDDD'])
    monkeypatch.setattr(appmodule, 'gerar_codigo_cca', lambda: next(sequencia))
    monkeypatch.setattr(appmodule, '_codigo_cca_em_uso', lambda codigo: False)

    resp = iniciar(client, cenario)
    assert resp.status_code == 200
    assert resp.get_json()['codigo_cca'] == 'CCA-CCCC-DDDD'
    # o cancelamento desfeito pelo rollback foi refeito na tentativa que deu certo
    assert contatos() == [(primeiro['codigo_cca'], 'cancelado'), ('CCA-CCCC-DDDD', 'ativo')]


def test_limite_de_tentativas_devolve_503_sem_loop(client, cenario, monkeypatch):
    chamadas = []

    def sempre_o_mesmo():
        chamadas.append(1)
        return 'CCA-EEEE-FFFF'

    monkeypatch.setattr(appmodule, 'gerar_codigo_cca', sempre_o_mesmo)
    monkeypatch.setattr(appmodule, '_codigo_cca_em_uso', lambda codigo: True)
    resp = iniciar(client, cenario)
    assert resp.status_code == 503
    assert resp.get_json() == {'erro': appmodule.MENSAGEM_CCA_INDISPONIVEL}
    assert len(chamadas) == appmodule.CCA_MAX_TENTATIVAS
    assert contatos() == []


def test_colisao_em_todas_as_tentativas_nao_gera_500_nem_registro_parcial(client, cenario, monkeypatch):
    ativo = iniciar(client, cenario).get_json()
    monkeypatch.setattr(appmodule, 'gerar_codigo_cca', lambda: ativo['codigo_cca'])
    monkeypatch.setattr(appmodule, '_codigo_cca_em_uso', lambda codigo: False)

    for rota in ('/api/escritorio/contato-seguro/iniciar', f"/api/escritorio/contato-seguro/reiniciar/{ativo['id']}"):
        corpo = {'advogado_id': cenario['adv'], 'processo_id': cenario['proc']['id']}
        resp = client.post(rota, json=corpo, headers=cenario['he'])
        assert resp.status_code == 503, rota
        assert 'IntegrityError' not in resp.get_data(as_text=True)
    # nada parcial: o CCA ativo continua ativo e nenhum registro novo foi criado
    assert contatos() == [(ativo['codigo_cca'], 'ativo')]


# ---------- isolamento, cliente e legado ----------

def test_isolamento_entre_escritorios(client, cenario):
    outro = montar_escritorio(client, 'cca@escritorio-b.com', '61955554444')
    cca_a = iniciar(client, cenario).get_json()
    assert client.post(f"/api/escritorio/contato-seguro/reiniciar/{cca_a['id']}", headers=outro['he']).status_code == 404
    assert client.post(f"/api/escritorio/contato-seguro/cancelar/{cca_a['id']}", headers=outro['he']).status_code == 404
    assert client.get('/api/escritorio/contato-seguro/listar', headers=outro['he']).get_json() == []


def test_cliente_continua_vendo_contato_ativo(client, cenario):
    iniciar(client, cenario)
    hc = headers_cliente(client, cenario)
    dados = client.get('/api/cliente/contato-seguro/ativo', headers=hc).get_json()
    assert dados['ativo'] is True and dados['canal'] == 'whatsapp'
    token = cenario['proc']['link_cliente_seguro'].rsplit('/', 1)[-1]
    publico = client.get(f'/api/cliente-publico/contato-ativo/{token}').get_json()
    assert publico['contato_ativo'] is True


def test_cca_antigo_no_formato_legado_continua_exibido(client, cenario):
    with appmodule.app.app_context():
        appmodule.db.session.add(appmodule.ContatoSeguro(
            escritorio_id=appmodule.db.session.get(appmodule.Processo, cenario['proc']['id']).escritorio_id,
            advogado_id=cenario['adv'], cliente_id=cenario['proc']['cliente_id'],
            processo_id=cenario['proc']['id'], codigo_cca='CCA-1234', canal='ligacao',
            status='cancelado', expira_em=appmodule.agora_utc() - timedelta(days=1),
        ))
        appmodule.db.session.commit()
        legado_id = appmodule.ContatoSeguro.query.filter_by(codigo_cca='CCA-1234').one().id

    lista = client.get('/api/escritorio/contato-seguro/listar', headers=cenario['he']).get_json()
    assert [c['codigo_cca'] for c in lista] == ['CCA-1234']
    pdf = client.get(f'/api/escritorio/relatorio/contato-seguro/{legado_id}/pdf', headers=cenario['he'])
    assert pdf.status_code == 200 and pdf.mimetype == 'application/pdf'
    novo = client.post(f'/api/escritorio/contato-seguro/reiniciar/{legado_id}', headers=cenario['he'])
    assert novo.status_code == 200 and FORMATO.match(novo.get_json()['codigo_cca'])


# ---------- rate limit ----------

def test_rate_limit_de_iniciar(client, cenario, monkeypatch):
    monkeypatch.setattr(appmodule, 'CCA_LIMITE_POR_MINUTO', 3)
    assert [iniciar(client, cenario).status_code for _ in range(4)] == [200, 200, 200, 429]


def test_rate_limit_de_reiniciar(client, cenario, monkeypatch):
    contato_id = iniciar(client, cenario).get_json()['id']
    monkeypatch.setattr(appmodule, 'CCA_LIMITE_POR_MINUTO', 3)
    rota = f'/api/escritorio/contato-seguro/reiniciar/{contato_id}'
    assert [client.post(rota, headers=cenario['he']).status_code for _ in range(4)] == [200, 200, 200, 429]


def test_limite_padrao_adotado():
    assert appmodule.CCA_LIMITE_POR_MINUTO == 30
    assert appmodule.CCA_MAX_TENTATIVAS == 5
