# -*- coding: utf-8 -*-
"""Correção 1 pós-Etapa 6: link seguro por processo de cliente desativado.

Com o cliente desativado, o link responde exatamente como um token inexistente e não grava
alertas nem análises. A verificação pública por código continua. Reativar restaura o link.
"""
import pytest

from conftest import appmodule, criar_vinculo_legado

db = appmodule.db
TELEFONE = '61908880001'
GETS = ('/api/cliente-publico/contato-seguro/{t}', '/api/cliente-publico/seguro/{t}',
        '/api/cliente-publico/contato-ativo/{t}')
ALERTA = {'tipo': 'pix', 'canal': 'whatsapp'}
ANALISE = {'texto_mensagem': 'mande um pix urgente para liberar o alvara', 'canal': 'whatsapp'}


def registrar(client, email):
    resp = client.post('/api/escritorio/registro', json={
        'nome': f'Escritorio {email}', 'email': email, 'senha': 'SenhaSegura123', 'aceite_termos': True,
    })
    assert resp.status_code == 200, resp.get_json()
    with appmodule.app.app_context():
        esc = appmodule.Escritorio.query.filter_by(email=email).first()
        esc.plano, esc.plano_expira = 'profissional', None
        db.session.commit()
    return {'Authorization': f"Bearer {resp.get_json()['token']}"}


@pytest.fixture()
def cenario(client):
    he = registrar(client, 'titular@esc-desat-link.com')
    adv = client.post('/api/escritorio/advogados', json={
        'nome': 'Dra. Desat', 'telefone_oficial': '61911998888'}, headers=he).get_json()['id']
    proc = client.post('/api/escritorio/processos', json={
        'advogado_id': adv, 'cliente_nome': 'Cliente Desat', 'cliente_telefone': TELEFONE,
    }, headers=he).get_json()
    return {'he': he, 'adv': adv, 'proc': proc, 'token': proc['link_cliente_seguro'].rsplit('/', 1)[-1]}


def desativar(client, c):
    assert client.post(f"/api/escritorio/clientes/{c['proc']['cliente_id']}/desativar", headers=c['he']).status_code == 200


def reativar(client, c):
    assert client.post(f"/api/escritorio/clientes/{c['proc']['cliente_id']}/reativar", headers=c['he']).status_code == 200


def contagens(pid):
    with appmodule.app.app_context():
        return (appmodule.TentativaContato.query.filter_by(processo_id=pid).count(),
                appmodule.AcessoPublicoLog.query.filter_by(processo_id=pid).count())


def test_cliente_ativo_continua_usando_o_link(client, cenario):
    t = cenario['token']
    for rota in GETS:
        assert client.get(rota.format(t=t)).status_code == 200
    assert client.post(f'/api/cliente-publico/registrar-alerta/{t}', json=ALERTA).status_code == 200
    assert client.post(f'/api/cliente-publico/analisar-golpe/{t}', json=ANALISE).status_code == 200
    assert contagens(cenario['proc']['id'])[0] >= 1


def test_desativado_recebe_a_mesma_resposta_de_link_inexistente(client, cenario):
    desativar(client, cenario)
    for rota in GETS:
        desativado = client.get(rota.format(t=cenario['token']))
        inexistente = client.get(rota.format(t='token-que-nao-existe-' + 'x' * 20))
        assert desativado.status_code == inexistente.status_code == 404
        assert desativado.get_json() == inexistente.get_json() == appmodule.MENSAGEM_LINK_INVALIDO


def test_desativado_nao_grava_alerta_nem_analise(client, cenario):
    pid, t = cenario['proc']['id'], cenario['token']
    desativar(client, cenario)
    antes = contagens(pid)

    alerta = client.post(f'/api/cliente-publico/registrar-alerta/{t}', json=ALERTA)
    alerta_inexistente = client.post('/api/cliente-publico/registrar-alerta/nao-existe-xyz', json=ALERTA)
    analise = client.post(f'/api/cliente-publico/analisar-golpe/{t}', json=ANALISE)

    # Mesma resposta genérica de sempre (não confirma se o link existe), sem gravar nada.
    assert alerta.status_code == alerta_inexistente.status_code == 200
    assert alerta.get_json() == alerta_inexistente.get_json()
    assert analise.status_code == 404
    assert contagens(pid) == antes


@pytest.mark.parametrize('pagina', ['/cliente/seguro/{t}', '/cliente/verificar/{t}', '/cliente/alerta/{t}'])
def test_paginas_continuam_existindo_e_a_api_recusa(client, cenario, pagina):
    desativar(client, cenario)
    assert client.get(pagina.format(t=cenario['token'])).status_code == 200


def test_historico_preservado(client, cenario):
    pid, t = cenario['proc']['id'], cenario['token']
    client.get(f'/api/cliente-publico/seguro/{t}')
    client.post(f'/api/cliente-publico/registrar-alerta/{t}', json=ALERTA)
    antes = contagens(pid)
    assert antes[0] == 1 and antes[1] >= 2

    desativar(client, cenario)
    client.get(f'/api/cliente-publico/seguro/{t}')
    reativar(client, cenario)

    assert contagens(pid) == antes
    lista = client.get('/api/escritorio/tentativas', headers=cenario['he'])
    assert lista.status_code == 200 and len(lista.get_json()) == 1


def test_reativar_restaura_o_link(client, cenario):
    t = cenario['token']
    desativar(client, cenario)
    assert client.get(f'/api/cliente-publico/seguro/{t}').status_code == 404
    reativar(client, cenario)
    assert client.get(f'/api/cliente-publico/seguro/{t}').status_code == 200
    assert client.post(f'/api/cliente-publico/analisar-golpe/{t}', json=ANALISE).status_code == 200


def test_verificacao_publica_por_codigo_continua(client, cenario):
    desativar(client, cenario)
    oficial = client.post('/api/publico/verificar', json={
        'codigo': cenario['proc']['codigo_unico'], 'numero': '61911998888', 'canal': 'whatsapp'})
    assert oficial.status_code == 200 and oficial.get_json()['resultado'] == 'confirmado'
    golpe = client.post('/api/publico/verificar', json={
        'codigo': cenario['proc']['codigo_unico'], 'numero': '61900000000', 'canal': 'whatsapp'})
    assert golpe.get_json()['resultado'] == 'numero_diferente'


def test_processo_arquivado_continua_invalido(client, cenario):
    with appmodule.app.app_context():
        db.session.get(appmodule.Processo, cenario['proc']['id']).status = 'arquivado'
        db.session.commit()
    assert client.get(f"/api/cliente-publico/seguro/{cenario['token']}").status_code == 404


# ---------- cliente compartilhado (vínculo legado entre escritórios) ----------

@pytest.fixture()
def compartilhado(client, cenario):
    h_b = registrar(client, 'b@esc-desat-link.com')
    adv_b = client.post('/api/escritorio/advogados', json={
        'nome': 'Dra. B', 'telefone_oficial': '61922998888'}, headers=h_b).get_json()['id']
    proc_b = criar_vinculo_legado(adv_b, TELEFONE)
    with appmodule.app.app_context():
        token_b = db.session.get(appmodule.Processo, proc_b['id']).token_cliente
    return {'h_b': h_b, 'token_a': cenario['token'], 'token_b': token_b}


def test_compartilhado_ativo_funciona_nos_dois_escritorios(client, cenario, compartilhado):
    for t in (compartilhado['token_a'], compartilhado['token_b']):
        assert client.get(f'/api/cliente-publico/seguro/{t}').status_code == 200


def test_compartilhado_nao_pode_ser_desativado_por_um_escritorio(client, cenario, compartilhado):
    """Isolamento existente (409) preservado: um escritório não derruba o link do outro."""
    resp = client.post(f"/api/escritorio/clientes/{cenario['proc']['cliente_id']}/desativar", headers=cenario['he'])
    assert resp.status_code == 409
    for t in (compartilhado['token_a'], compartilhado['token_b']):
        assert client.get(f'/api/cliente-publico/seguro/{t}').status_code == 200


def test_compartilhado_desativado_globalmente_bloqueia_os_dois(client, cenario, compartilhado):
    """O status ativo é global do cliente; desativação (legado/suporte) vale para todos os links."""
    with appmodule.app.app_context():
        db.session.get(appmodule.Cliente, cenario['proc']['cliente_id']).ativo = False
        db.session.commit()
    for t in (compartilhado['token_a'], compartilhado['token_b']):
        assert client.get(f'/api/cliente-publico/seguro/{t}').status_code == 404
