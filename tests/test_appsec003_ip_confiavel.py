# -*- coding: utf-8 -*-
"""APPSEC-003: um X-Forwarded-For forjado não escolhe a chave do rate limit nem o IP dos logs.

No Render o IP vem do CF-Connecting-IP (sobrescrito pela Cloudflare). O X-Forwarded-For só é
usado com TRUSTED_PROXY_COUNT explícito. Local/testes usam remote_addr. Operações sensíveis
também contam por conta/identidade, qualquer que seja o IP.
"""
import inspect

import pytest

from conftest import appmodule

IP_LB = '10.0.0.1'  # remote_addr visto pela aplicação atrás do load balancer
SENHA = 'SenhaSegura123'


def post(client, rota, corpo, cf=None, xff=None, remote=IP_LB):
    headers = {}
    if cf:
        headers['CF-Connecting-IP'] = cf
    if xff:
        headers['X-Forwarded-For'] = xff
    return client.post(rota, json=corpo, headers=headers, environ_base={'REMOTE_ADDR': remote})


def ip_de(headers=None, remote=IP_LB):
    with appmodule.app.test_request_context('/', headers=headers or {}, environ_base={'REMOTE_ADDR': remote}):
        return appmodule._ip_confiavel()


@pytest.fixture()
def no_render(monkeypatch):
    monkeypatch.setattr(appmodule, 'CONFIAR_CF_CONNECTING_IP', True)
    monkeypatch.setattr(appmodule, 'PROXIES_CONFIAVEIS', 0)


@pytest.fixture()
def local(monkeypatch):
    monkeypatch.setattr(appmodule, 'CONFIAR_CF_CONNECTING_IP', False)
    monkeypatch.setattr(appmodule, 'PROXIES_CONFIAVEIS', 0)


@pytest.fixture()
def proxy_explicito(monkeypatch):
    monkeypatch.setattr(appmodule, 'CONFIAR_CF_CONNECTING_IP', False)
    monkeypatch.setattr(appmodule, 'PROXIES_CONFIAVEIS', 1)


def registrar_escritorio(client, email):
    resp = client.post('/api/escritorio/registro', json={'nome': 'Esc IP', 'email': email, 'senha': SENHA})
    assert resp.status_code == 200, resp.get_json()


def login_errado(client, email, **kw):
    return post(client, '/api/escritorio/login', {'email': email, 'senha': 'errada'}, **kw)


# ---------- origem do IP ----------

def test_padrao_local_e_testes_nao_confia_em_cabecalhos_de_proxy():
    assert appmodule.CONFIAR_CF_CONNECTING_IP is False
    assert appmodule.PROXIES_CONFIAVEIS == 0


def test_local_ignora_cf_connecting_ip_e_x_forwarded_for(local):
    headers = {'CF-Connecting-IP': '203.0.113.5', 'X-Forwarded-For': '6.6.6.6, 203.0.113.5'}
    assert ip_de(headers, remote='192.0.2.10') == '192.0.2.10'


def test_cf_connecting_ip_valido_prevalece(no_render):
    assert ip_de({'CF-Connecting-IP': '203.0.113.5'}) == '203.0.113.5'
    assert ip_de({'CF-Connecting-IP': ' 2001:db8::1 '}) == '2001:db8::1'


def test_cf_connecting_ip_prevalece_sobre_xff_arbitrario(no_render):
    headers = {'CF-Connecting-IP': '203.0.113.5', 'X-Forwarded-For': '6.6.6.6, 7.7.7.7'}
    assert ip_de(headers) == '203.0.113.5'


@pytest.mark.parametrize('valor', ['', 'nao-e-ip', '999.1.1.1', '<script>', '6.6.6.6, 7.7.7.7'])
def test_cf_connecting_ip_invalido_cai_no_remote_addr_sem_usar_xff(no_render, valor):
    assert ip_de({'CF-Connecting-IP': valor, 'X-Forwarded-For': '6.6.6.6'}) == IP_LB


def test_cf_connecting_ip_duplicado_e_ignorado(no_render):
    with appmodule.app.test_request_context(
        '/', headers=[('CF-Connecting-IP', '6.6.6.6'), ('CF-Connecting-IP', '203.0.113.5')],
        environ_base={'REMOTE_ADDR': IP_LB},
    ):
        assert appmodule._ip_confiavel() == IP_LB


def test_sem_cf_connecting_ip_nao_confia_no_xff_sem_configuracao(no_render):
    assert ip_de({'X-Forwarded-For': '6.6.6.6, 203.0.113.5'}) == IP_LB


def test_xff_so_com_configuracao_explicita_e_pelo_fim_da_lista(proxy_explicito):
    assert ip_de({'X-Forwarded-For': '6.6.6.6, 7.7.7.7, 203.0.113.5'}) == '203.0.113.5'
    with appmodule.app.test_request_context(
        '/', headers=[('X-Forwarded-For', '6.6.6.6'), ('X-Forwarded-For', '203.0.113.6')],
        environ_base={'REMOTE_ADDR': IP_LB},
    ):
        assert appmodule._ip_confiavel() == '203.0.113.6'
    assert ip_de({'X-Forwarded-For': 'nao-e-ip'}) == IP_LB
    assert ip_de() == IP_LB


def test_xff_com_cadeia_mais_curta_que_a_configurada_usa_remote_addr(monkeypatch):
    monkeypatch.setattr(appmodule, 'CONFIAR_CF_CONNECTING_IP', False)
    monkeypatch.setattr(appmodule, 'PROXIES_CONFIAVEIS', 2)
    assert ip_de({'X-Forwarded-For': '203.0.113.5'}) == IP_LB
    assert ip_de({'X-Forwarded-For': '6.6.6.6, 203.0.113.5, 10.1.1.1'}) == '203.0.113.5'


# ---------- login do escritório ----------

def test_xff_forjado_nao_renova_tentativas_no_render(client, no_render):
    status = [login_errado(client, 'alvo@x.com', cf='203.0.113.9', xff=f'6.6.6.{i}').status_code
              for i in range(appmodule.MAX_TENTATIVAS + 1)]
    assert status == [401] * appmodule.MAX_TENTATIVAS + [429]


def test_xff_forjado_nao_renova_tentativas_local(client, local):
    status = [login_errado(client, 'alvo@x.com', xff=f'6.6.6.{i}', remote='192.0.2.20').status_code
              for i in range(appmodule.MAX_TENTATIVAS + 1)]
    assert status == [401] * appmodule.MAX_TENTATIVAS + [429]


def test_xff_forjado_sem_cf_cai_no_mesmo_remote_addr(client, no_render):
    status = [login_errado(client, 'alvo@x.com', xff=f'6.6.6.{i}').status_code
              for i in range(appmodule.MAX_TENTATIVAS + 1)]
    assert status == [401] * appmodule.MAX_TENTATIVAS + [429]


def test_limite_por_conta_vale_mesmo_trocando_de_ip_real(client, no_render):
    status = [login_errado(client, 'alvo@x.com', cf=f'198.51.100.{i}').status_code
              for i in range(appmodule.MAX_FALHAS_POR_CONTA + 1)]
    assert status == [401] * appmodule.MAX_FALHAS_POR_CONTA + [429]


def test_limite_por_conta_nao_revela_se_a_conta_existe(client, no_render):
    registrar_escritorio(client, 'existe@x.com')
    respostas = {}
    for email in ('existe@x.com', 'naoexiste@x.com'):
        for i in range(appmodule.MAX_FALHAS_POR_CONTA):
            login_errado(client, email, cf=f'198.51.100.{i}')
        bloqueio = login_errado(client, email, cf='198.51.100.250')
        respostas[email] = (bloqueio.status_code, bloqueio.get_json()['erro'].split(' Tente')[0])
    assert respostas['existe@x.com'] == respostas['naoexiste@x.com'] == (429, 'Muitas tentativas de login.')


def test_ip_diferente_continua_podendo_entrar_e_sucesso_limpa_contadores(client, no_render):
    registrar_escritorio(client, 'normal@x.com')
    for _ in range(appmodule.MAX_TENTATIVAS):
        login_errado(client, 'normal@x.com', cf='203.0.113.40')
    assert login_errado(client, 'normal@x.com', cf='203.0.113.40').status_code == 429
    ok = post(client, '/api/escritorio/login', {'email': 'normal@x.com', 'senha': SENHA}, cf='203.0.113.41')
    assert ok.status_code == 200
    assert not any(chave.startswith(appmodule.PREFIXO_CHAVE_CONTA) for chave in appmodule._tentativas_login)


# ---------- login do cliente ----------

def test_login_do_cliente_limitado_por_ip_e_por_telefone(client, no_render):
    corpo = {'telefone': '61900001111', 'senha': 'errada'}
    por_ip = [post(client, '/api/cliente/login', corpo, cf='203.0.113.50', xff=f'6.6.6.{i}').status_code
              for i in range(appmodule.MAX_TENTATIVAS + 1)]
    assert por_ip == [401] * appmodule.MAX_TENTATIVAS + [429]

    appmodule._tentativas_login.clear()
    por_conta = [post(client, '/api/cliente/login', corpo, cf=f'198.51.100.{i}').status_code
                 for i in range(appmodule.MAX_FALHAS_POR_CONTA + 1)]
    assert por_conta == [401] * appmodule.MAX_FALHAS_POR_CONTA + [429]


# ---------- confirmação de e-mail, recuperação ----------

def test_confirmacao_de_email_limitada_por_email_mesmo_variando_ip(client, no_render):
    corpo = {'email': 'pendente@x.com', 'codigo': '000000'}
    status = [post(client, '/api/comercial/confirmar-email', corpo, cf=f'198.51.100.{i}').status_code
              for i in range(11)]
    assert status == [400] * 10 + [429]


def test_confirmacao_de_email_continua_limitada_por_ip(client, no_render):
    status = [post(client, '/api/comercial/confirmar-email', {'email': 'p@x.com', 'codigo': '000000'},
                   cf='203.0.113.60', xff=f'6.6.6.{i}').status_code for i in range(9)]
    assert status == [400] * 8 + [429]


def test_confirmacao_de_email_valida_continua_funcionando(client, no_render):
    cadastro = post(client, '/api/comercial/registro', {
        'nome': 'Esc Confirma', 'email': 'confirma@x.com', 'senha': SENHA, 'tipo_pessoa': 'PJ',
        'cnpj': '11222333000181', 'plano': 'escritorio'}, cf='203.0.113.61')
    assert cadastro.status_code == 201, cadastro.get_json()
    resp = post(client, '/api/comercial/confirmar-email', {
        'email': 'confirma@x.com', 'codigo': cadastro.get_json()['codigo_dev']}, cf='203.0.113.61')
    assert resp.status_code == 200


def test_esqueci_senha_limitado_por_email_e_telefone_mesmo_variando_ip(client, no_render):
    for rota, corpo in (('/api/escritorio/esqueci-senha', {'email': 'qualquer@x.com'}),
                        ('/api/cliente/esqueci-senha', {'telefone': '61900002222'})):
        status = [post(client, rota, corpo, cf=f'198.51.100.{i}').status_code for i in range(6)]
        assert status == [200] * 5 + [429], rota


def test_reenvio_de_confirmacao_limitado_por_email(client, no_render):
    status = [post(client, '/api/comercial/reenviar-confirmacao', {'email': 'r@x.com'},
                   cf=f'198.51.100.{i}').status_code for i in range(4)]
    assert status == [200] * 3 + [429]


@pytest.mark.parametrize('rota', ['/api/escritorio/redefinir-senha', '/api/cliente/redefinir-senha'])
def test_redefinicao_com_token_limitada_por_ip(client, no_render, rota):
    status = [post(client, rota, {'token': f'invalido-{i}', 'nova_senha': SENHA},
                   cf='203.0.113.70', xff=f'6.6.6.{i}').status_code for i in range(11)]
    assert status == [400] * 10 + [429]


# ---------- verificação pública ----------

def test_verificacao_publica_limitada_por_ip_sem_bypass_por_xff(client, no_render):
    status = [post(client, '/api/publico/verificar', {'codigo': f'COD{i:05d}', 'numero': '61900000000'},
                   cf='203.0.113.80', xff=f'6.6.6.{i}').status_code for i in range(31)]
    assert status == [200] * 30 + [429]


def test_verificacao_publica_limitada_por_codigo_mesmo_variando_ip(client, no_render):
    status = [post(client, '/api/publico/verificar', {'codigo': 'ABCDEFGH', 'numero': '61900000000'},
                   cf=f'198.51.100.{i}').status_code for i in range(21)]
    assert status == [200] * 20 + [429]


# ---------- logs pseudonimizados ----------

def test_logs_usam_cf_connecting_ip_pseudonimizado(client, no_render):
    client.get('/api/cliente-publico/contato-ativo/token-inexistente',
               headers={'CF-Connecting-IP': '198.51.100.77', 'X-Forwarded-For': '6.6.6.6'},
               environ_base={'REMOTE_ADDR': IP_LB})
    with appmodule.app.app_context():
        ips = {log.ip for log in appmodule.AcessoPublicoLog.query.all()}
    assert ips == {appmodule._pseudonimizar_ip('198.51.100.77')}
    assert ips.isdisjoint({'198.51.100.77', appmodule._pseudonimizar_ip('6.6.6.6')})


def test_logs_locais_usam_remote_addr_pseudonimizado(client, local):
    client.get('/api/cliente-publico/contato-ativo/token-inexistente',
               headers={'CF-Connecting-IP': '198.51.100.77', 'X-Forwarded-For': '6.6.6.6'},
               environ_base={'REMOTE_ADDR': '192.0.2.30'})
    with appmodule.app.app_context():
        ips = {log.ip for log in appmodule.AcessoPublicoLog.query.all()}
    assert ips == {appmodule._pseudonimizar_ip('192.0.2.30')}


def test_codigo_nao_le_mais_x_forwarded_for_diretamente():
    fonte = inspect.getsource(appmodule)
    assert fonte.count("'X-Forwarded-For'") == 1  # só dentro de _ip_confiavel
    assert fonte.count("'CF-Connecting-IP'") == 1
    assert "split(',')[0]" not in fonte
