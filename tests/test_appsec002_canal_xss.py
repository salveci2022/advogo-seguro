# -*- coding: utf-8 -*-
"""APPSEC-002: o campo `canal` nunca entra como HTML/JS no painel de Tentativas.

Defesa em profundidade: o backend só aceita canais da lista (rotas públicas, do
cliente e do escritório) e o frontend escapa qualquer valor fora do mapa.
"""
import os
import re

import pytest

from conftest import appmodule, cliente_ja_criou_senha_pessoal

TELEFONE = '61988887777'
OFICIAL = '61911112222'
SCRIPT = '<script>alert(1)</script>'
ONERROR = '<img src=x onerror=alert(1)>'
PAYLOADS = [SCRIPT, ONERROR, 'sms', 'WhatsApp<b>', 123, {'x': 1}, ['whatsapp']]
RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def registrar(client, email='canal@escritorio.com'):
    resp = client.post('/api/escritorio/registro', json={
        'nome': 'Escritorio Canal', 'email': email, 'senha': 'SenhaSegura123'
    })
    assert resp.status_code == 200, resp.get_json()
    with appmodule.app.app_context():
        escritorio = appmodule.Escritorio.query.filter_by(email=email).first()
        escritorio.plano = 'profissional'
        escritorio.plano_expira = None
        appmodule.db.session.commit()
    return {'Authorization': f"Bearer {resp.get_json()['token']}"}


@pytest.fixture()
def cenario(client):
    he = registrar(client)
    adv = client.post('/api/escritorio/advogados', json={
        'nome': 'Dra. Canal', 'telefone_oficial': OFICIAL
    }, headers=he).get_json()['id']
    proc = client.post('/api/escritorio/processos', json={
        'advogado_id': adv, 'cliente_nome': 'Cliente Canal', 'cliente_telefone': TELEFONE
    }, headers=he).get_json()
    cliente_ja_criou_senha_pessoal(TELEFONE)
    login = client.post('/api/cliente/login', json={'telefone': TELEFONE, 'senha': proc['senha_temporaria']})
    hc = {'Authorization': f"Bearer {login.get_json()['token']}"}
    token = proc['link_cliente_seguro'].rsplit('/', 1)[-1]
    return {'he': he, 'hc': hc, 'codigo': proc['codigo_unico'], 'token': token, 'adv': adv}


def rotas_com_canal(c):
    """(rota, corpo, headers) de toda rota que grava TentativaContato com canal."""
    golpe = 'URGENTE: pague a taxa via pix agora para liberar o alvará'
    return [
        ('/api/publico/verificar', {'codigo': c['codigo'], 'numero': '61900000000'}, {}),
        ('/api/ia/analisar-golpe', {'texto_mensagem': golpe, 'codigo_processo': c['codigo'],
                                    'numero_suspeito': '61900000000'}, {}),
        (f"/api/cliente-publico/registrar-alerta/{c['token']}", {'tipo': 'nao_reconheco'}, {}),
        (f"/api/cliente-publico/analisar-golpe/{c['token']}", {'texto_mensagem': golpe}, {}),
        ('/api/cliente/verificar', {'codigo': c['codigo'], 'numero': '61900000000'}, c['hc']),
        ('/api/cliente/contato-seguro/verificar', {}, c['hc']),
        ('/api/cliente/contato-seguro/registrar-suspeita', {'numero': '61900000000'}, c['hc']),
    ]


def canais_no_banco():
    with appmodule.app.app_context():
        return [t.canal for t in appmodule.TentativaContato.query.all()]


def test_canal_valido_continua_funcionando_em_todas_as_rotas(client, cenario):
    for rota, corpo, headers in rotas_com_canal(cenario):
        resp = client.post(rota, json=dict(corpo, canal='ligacao'), headers=headers)
        assert resp.status_code == 200, (rota, resp.get_json())
    canais = canais_no_banco()
    assert len(canais) == len(rotas_com_canal(cenario))
    assert set(canais) == {'ligacao'}

    painel = client.get('/api/escritorio/tentativas', headers=cenario['he']).get_json()
    assert {t['canal'] for t in painel} == {'ligacao'}


def test_canal_ausente_usa_padrao_whatsapp(client, cenario):
    resp = client.post('/api/publico/verificar', json={'codigo': cenario['codigo'], 'numero': '61900000000'})
    assert resp.status_code == 200
    assert canais_no_banco() == ['whatsapp']


def test_canal_e_normalizado_para_minusculas(client, cenario):
    resp = client.post('/api/publico/verificar', json={
        'codigo': cenario['codigo'], 'numero': '61900000000', 'canal': ' Email '
    })
    assert resp.status_code == 200
    assert canais_no_banco() == ['email']


@pytest.mark.parametrize('payload', PAYLOADS, ids=['script', 'onerror', 'fora_da_lista', 'html', 'int', 'dict', 'list'])
def test_canal_invalido_e_recusado_em_todas_as_rotas_sem_gravar(client, cenario, payload):
    for rota, corpo, headers in rotas_com_canal(cenario):
        resp = client.post(rota, json=dict(corpo, canal=payload), headers=headers)
        assert resp.status_code == 400, (rota, resp.status_code)
        assert resp.get_json()['erro'] == appmodule.MENSAGEM_CANAL_INVALIDO
    assert canais_no_banco() == []
    with appmodule.app.app_context():
        assert appmodule.AcessoPublicoLog.query.filter(
            appmodule.AcessoPublicoLog.acao.in_(['nao_reconheco', 'analisou_ia'])
        ).count() == 0


def test_rotas_publicas_nao_gravam_script_nem_onerror(client, cenario):
    for rota, corpo, headers in rotas_com_canal(cenario)[:4]:
        for payload in (SCRIPT, ONERROR):
            assert client.post(rota, json=dict(corpo, canal=payload), headers=headers).status_code == 400
    texto = client.get('/api/escritorio/tentativas', headers=cenario['he']).get_data(as_text=True)
    assert '<script' not in texto and 'onerror' not in texto


def test_contato_seguro_do_escritorio_continua_validando_canal(client, cenario):
    resp = client.post('/api/escritorio/contato-seguro/iniciar', json={
        'advogado_id': cenario['adv'], 'processo_id': None, 'cliente_id': None, 'canal': ONERROR
    }, headers=cenario['he'])
    assert resp.status_code == 400


def _funcao_js(nome_template, nome_funcao):
    with open(os.path.join(RAIZ, 'templates', nome_template), encoding='utf-8') as arquivo:
        html = arquivo.read()
    corpo = re.search(r'function ' + nome_funcao + r'\(c\) \{(.*?)\n\}', html, re.S)
    assert corpo, f'{nome_funcao} não encontrada em {nome_template}'
    return html, corpo.group(1)


@pytest.mark.parametrize('template', ['tentativas.html', 'contato_seguro.html'])
def test_frontend_escapa_canal_fora_do_mapa(template):
    """Verificação estática: o fallback de canalLabel passa por escapeHtml (que usa textContent)."""
    html, corpo = _funcao_js(template, 'canalLabel')
    retorno = re.search(r'return (.*);', corpo).group(1)
    assert retorno.startswith('m[c] || escapeHtml(')
    assert 'div.textContent = str' in html


def test_painel_tentativas_nao_usa_canal_bruto():
    with open(os.path.join(RAIZ, 'templates', 'tentativas.html'), encoding='utf-8') as arquivo:
        html = arquivo.read()
    assert '${t.canal}' not in html
    assert '${canalLabel(t.canal)}' in html
