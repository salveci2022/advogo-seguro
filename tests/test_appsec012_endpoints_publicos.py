# -*- coding: utf-8 -*-
"""APPSEC-012: rotas públicas que gravam dados têm limite por IP e por identidade estável
(token do link / código do processo), tamanho máximo de campos e não gravam nada para
token inválido. O token bruto nunca aparece em log nem nas chaves de rate limit.
"""
import json
import logging

import pytest

from conftest import appmodule

TELEFONE = '61922221111'


@pytest.fixture()
def cenario(client):
    resp = client.post('/api/escritorio/registro', json={'nome': 'Esc Pub', 'email': 'pub@x.com', 'senha': 'SenhaSegura123'})
    he = {'Authorization': f"Bearer {resp.get_json()['token']}"}
    with appmodule.app.app_context():
        e = appmodule.Escritorio.query.filter_by(email='pub@x.com').one()
        e.plano, e.plano_expira = 'profissional', None
        appmodule.db.session.commit()
    adv = client.post('/api/escritorio/advogados', json={'nome': 'Dra Pub', 'telefone_oficial': '61911112222'},
                      headers=he).get_json()['id']
    proc = client.post('/api/escritorio/processos', json={
        'advogado_id': adv, 'cliente_nome': 'Cliente Pub', 'cliente_telefone': TELEFONE}, headers=he).get_json()
    return {'token': proc['link_cliente_seguro'].rsplit('/', 1)[-1], 'codigo': proc['codigo_unico']}


@pytest.fixture()
def ips_rotativos(monkeypatch):
    """Simula o Render: o IP vem do CF-Connecting-IP, e o atacante usa um IP real diferente por requisição."""
    monkeypatch.setattr(appmodule, 'CONFIAR_CF_CONNECTING_IP', True)
    contador = iter(range(1, 100000))
    return lambda: {'CF-Connecting-IP': f'198.51.{next(contador) // 250}.{next(contador) % 250 + 1}'}


def contagens():
    with appmodule.app.app_context():
        return appmodule.TentativaContato.query.count(), appmodule.AcessoPublicoLog.query.count()


def alerta(client, token, corpo=None, headers=None):
    return client.post(f'/api/cliente-publico/registrar-alerta/{token}', json=corpo or {'tipo': 'pix'}, headers=headers or {})


# ---------- limites por IP ----------

def test_contato_ativo_agora_tem_limite_por_ip(client):
    status = [client.get(f'/api/cliente-publico/contato-ativo/token-falso-{i}').status_code for i in range(61)]
    assert status[:60] == [404] * 60 and status[60] == 429


def test_verificacao_publica_continua_limitada_por_ip(client, cenario):
    status = [client.post('/api/publico/verificar', json={'codigo': f'X{i:07d}', 'numero': '1'}).status_code
              for i in range(31)]
    assert status == [200] * 30 + [429]


# ---------- limites por identidade estável, com IP rotativo ----------

def test_leitura_do_link_limitada_por_token_mesmo_trocando_ip(client, cenario, ips_rotativos):
    maximo = appmodule.LIMITE_LINK_LEITURA[0]
    rota = f"/api/cliente-publico/contato-ativo/{cenario['token']}"
    status = [client.get(rota, headers=ips_rotativos()).status_code for _ in range(maximo + 1)]
    assert status == [200] * maximo + [429]


def test_escrita_do_link_limitada_por_token_e_429_nao_grava(client, cenario, ips_rotativos):
    maximo = appmodule.LIMITE_LINK_ESCRITA[0]
    for _ in range(maximo):
        assert alerta(client, cenario['token'], headers=ips_rotativos()).status_code == 200
    antes = contagens()
    assert antes == (maximo, maximo)
    bloqueado = alerta(client, cenario['token'], headers=ips_rotativos())
    assert bloqueado.status_code == 429
    analise = client.post(f"/api/cliente-publico/analisar-golpe/{cenario['token']}",
                          json={'texto_mensagem': 'pague o pix urgente da taxa do alvará'}, headers=ips_rotativos())
    assert analise.status_code == 429  # escrita compartilha o limite do token
    assert contagens() == antes        # nada parcial


def test_analise_publica_limitada_por_codigo_mesmo_trocando_ip(client, cenario, ips_rotativos):
    corpo = {'texto_mensagem': 'pague o pix urgente', 'codigo_processo': cenario['codigo'], 'numero_suspeito': '61900000000'}
    status = [client.post('/api/ia/analisar-golpe', json=corpo, headers=ips_rotativos()).status_code for _ in range(21)]
    assert status == [200] * 20 + [429]


def test_verificacao_publica_limitada_por_codigo_mesmo_trocando_ip(client, cenario, ips_rotativos):
    corpo = {'codigo': cenario['codigo'], 'numero': '61900000000'}
    status = [client.post('/api/publico/verificar', json=corpo, headers=ips_rotativos()).status_code for _ in range(21)]
    assert status == [200] * 20 + [429]
    assert contagens()[0] == 20


# ---------- token inválido ----------

def test_token_invalido_resposta_generica_e_nada_gravado(client, cenario):
    for rota in ('/api/cliente-publico/contato-seguro/{}', '/api/cliente-publico/seguro/{}',
                 '/api/cliente-publico/contato-ativo/{}'):
        resp = client.get(rota.format('token-que-nao-existe'))
        assert resp.status_code == 404 and resp.get_json() == appmodule.MENSAGEM_LINK_INVALIDO
    falso = alerta(client, 'token-que-nao-existe')
    verdadeiro = alerta(client, cenario['token'])
    assert falso.status_code == verdadeiro.status_code == 200
    assert falso.get_json() == verdadeiro.get_json()  # não confirma se o link existe
    analise = client.post('/api/cliente-publico/analisar-golpe/token-que-nao-existe', json={'texto_mensagem': 'oi'})
    assert analise.status_code == 404 and analise.get_json() == appmodule.MENSAGEM_LINK_INVALIDO
    assert contagens() == (1, 1)  # só o alerta do token verdadeiro


def test_token_gigante_tratado_como_invalido(client):
    resp = client.get('/api/cliente-publico/contato-ativo/' + 'a' * 5000)
    assert resp.status_code == 404 and contagens() == (0, 0)


def test_token_bruto_nao_aparece_em_log_nem_nas_chaves_de_limite(client, cenario, caplog, ips_rotativos):
    caplog.set_level(logging.DEBUG)
    token = cenario['token']
    for _ in range(appmodule.LIMITE_LINK_ESCRITA[0] + 2):
        alerta(client, token, headers=ips_rotativos())
    client.get(f'/api/cliente-publico/contato-seguro/{token}')
    assert token not in caplog.text
    chaves = ' '.join(list(appmodule._tentativas_acoes) + list(appmodule._tentativas_login))
    assert token not in chaves and 'link-seguro-escrita:' in chaves


# ---------- tamanho e tipo dos campos ----------

def test_payload_acima_do_limite_global_e_rejeitado(client):
    corpo = json.dumps({'codigo': 'ABC', 'descricao': 'x' * (appmodule.app.config['MAX_CONTENT_LENGTH'] + 1)})
    resp = client.post('/api/publico/verificar', data=corpo, content_type='application/json')
    assert resp.status_code == 413
    assert contagens() == (0, 0)


@pytest.mark.parametrize('rota_corpo', [
    ('/api/publico/verificar', {'codigo': '{codigo}', 'numero': '1', 'descricao': 'x' * 501}),
    ('/api/publico/verificar', {'codigo': 'C' * 13, 'numero': '1'}),
    ('/api/publico/verificar', {'codigo': 12345678, 'numero': '1'}),
    ('/api/publico/verificar', {'codigo': '{codigo}', 'numero': ['1']}),
    ('/api/ia/analisar-golpe', {'texto_mensagem': 'x' * 5001}),
    ('/api/ia/analisar-golpe', {'texto_mensagem': 'pix', 'numero_suspeito': '9' * 21, 'codigo_processo': '{codigo}'}),
    ('/api/ia/analisar-golpe', {'texto_mensagem': 'pix', 'codigo_processo': {'x': 1}}),
    ('/api/cliente-publico/registrar-alerta/{token}', {'tipo': 'pix', 'descricao': 'x' * 501}),
    ('/api/cliente-publico/registrar-alerta/{token}', {'tipo': 'pix', 'numero': '9' * 21}),
    ('/api/cliente-publico/registrar-alerta/{token}', {'tipo': '<script>'}),
    ('/api/cliente-publico/registrar-alerta/{token}', {'tipo': 'pix', 'descricao': {'a': 1}}),
    ('/api/cliente-publico/analisar-golpe/{token}', {'texto_mensagem': 'x' * 5001}),
], ids=['descricao_501', 'codigo_13', 'codigo_int', 'numero_lista', 'texto_5001', 'numero_21',
        'codigo_dict', 'alerta_descricao_501', 'alerta_numero_21', 'alerta_tipo_livre', 'alerta_descricao_dict',
        'analise_link_5001'])
def test_campo_invalido_ou_grande_demais_e_recusado_sem_gravar(client, cenario, rota_corpo):
    rota, corpo = rota_corpo
    corpo = {k: (v.format(**cenario) if isinstance(v, str) and '{' in v else v) for k, v in corpo.items()}
    resp = client.post(rota.format(**cenario), json=corpo)
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert contagens() == (0, 0)


def test_campos_normais_e_no_limite_continuam_funcionando(client, cenario):
    resp = client.post('/api/publico/verificar', json={
        'codigo': cenario['codigo'], 'numero': '(61) 90000-0000', 'descricao': 'd' * 500})
    assert resp.status_code == 200 and resp.get_json()['resultado'] == 'numero_diferente'
    resp = alerta(client, cenario['token'], {'tipo': 'nao_reconheco', 'numero': '(61) 98888-7777', 'descricao': 'Ligou pedindo Pix'})
    assert resp.status_code == 200
    resp = client.post('/api/ia/analisar-golpe', json={'texto_mensagem': 'p' * 5000, 'codigo_processo': cenario['codigo']})
    assert resp.status_code == 200
    with appmodule.app.app_context():
        descricoes = sorted(t.descricao for t in appmodule.TentativaContato.query.all())
    assert descricoes == ['Ligou pedindo Pix', 'd' * 500]


def test_verificacao_publica_legitima_nao_e_bloqueada(client, cenario):
    for numero in ('61911112222', '61900000000', '61911112222', '61900000001', '61911112222'):
        assert client.post('/api/publico/verificar', json={'codigo': cenario['codigo'], 'numero': numero}).status_code == 200


def test_cadastro_recusa_campos_gigantes_e_aceita_normais(client):
    grande = client.post('/api/comercial/registro', json={
        'nome': 'N' * 201, 'email': 'g@x.com', 'senha': 'SenhaSegura123', 'tipo_pessoa': 'PJ',
        'cnpj': '11222333000181', 'plano': 'escritorio'})
    assert grande.status_code == 400
    normal = client.post('/api/comercial/registro', json={
        'nome': 'Escritório Normal', 'email': 'normal@x.com', 'senha': 'SenhaSegura123', 'tipo_pessoa': 'PJ',
        'cnpj': '11222333000181', 'plano': 'escritorio'})
    assert normal.status_code == 201, normal.get_json()


def test_identificador_gigante_nao_vira_chave_gigante_em_memoria(client):
    client.post('/api/escritorio/login', json={'email': 'a' * 100000 + '@x.com', 'senha': 'x'})
    client.post('/api/cliente/esqueci-senha', json={'telefone': '9' * 100000})
    assert max(len(k) for k in list(appmodule._tentativas_login) + list(appmodule._tentativas_acoes)) < 200
