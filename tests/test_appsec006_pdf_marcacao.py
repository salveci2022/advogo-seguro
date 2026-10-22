# -*- coding: utf-8 -*-
"""APPSEC-006: texto dinâmico nos PDFs (ReportLab) é sempre texto, nunca marcação.

Antes, um <img src="http://..."> numa descrição pública fazia o servidor buscar a URL ao
montar o parágrafo, <a href> virava link no relatório e tag malformada gerava erro 500.
Nenhum teste acessa a rede: urlopen e ImageReader do ReportLab são substituídos por espiões.
"""
import pytest
import reportlab.lib.utils as rl_utils
import reportlab.platypus.paraparser as rl_paraparser
from reportlab.platypus import Paragraph, Table

from conftest import appmodule

SCRIPT = '<script>alert(1)</script>'
IMG_URL = '<img src="http://169.254.169.254/latest/meta-data" width="10" height="10"/>'
IMG_SEM_TAMANHO = '<img src="http://10.0.0.5/interno.png"/>'
IMG_ARQUIVO = '<img src="/etc/passwd"/>'
LINK = '<a href="http://phishing.example/pague">Clique aqui para liberar</a>'
MALFORMADAS = ['<b>sem fechar', '</para>fim', '<font size="90" color="red">GRANDE', '<br/><br/>', '<<>>', '&amp; &#x41; &bogus;']
ESPECIAIS = 'Tom & Jerry <ltda> > 5 "aspas" \'apostrofo\''
MALICIOSOS = [SCRIPT, IMG_URL, IMG_SEM_TAMANHO, IMG_ARQUIVO, LINK, ESPECIAIS] + MALFORMADAS


@pytest.fixture(autouse=True)
def sem_rede(monkeypatch):
    """Registra qualquer tentativa de carregar recurso externo e garante que nada sai da máquina."""
    chamadas = []

    def urlopen_espiao(url, *args, **kwargs):
        chamadas.append(('urlopen', url))
        raise OSError('rede bloqueada no teste')

    class ImageReaderEspiao:
        def __init__(self, origem, *args, **kwargs):
            chamadas.append(('ImageReader', origem))
            raise OSError('imagem bloqueada no teste')

    monkeypatch.setattr(rl_utils, 'urlopen', urlopen_espiao)
    monkeypatch.setattr(rl_paraparser, 'ImageReader', ImageReaderEspiao)
    return chamadas


@pytest.fixture()
def capturado(monkeypatch):
    """Captura o texto exibido (sem marcação), links e imagens de cada PDF gerado."""
    resultado = {'textos': [], 'links': [], 'imagens': []}
    original = appmodule._pdf_response

    def coletar(item):
        if isinstance(item, Paragraph):
            resultado['textos'].append(''.join(getattr(f, 'text', '') for f in item.frags))
            for frag in item.frags:
                if getattr(frag, 'link', None):
                    resultado['links'].append(frag.link)
                if getattr(frag, 'cbDefn', None) is not None:
                    resultado['imagens'].append(frag.cbDefn)
        elif isinstance(item, Table):
            for linha in item._cellvalues:
                for celula in linha:
                    if isinstance(celula, str):
                        resultado['textos'].append(celula)
                    else:
                        coletar(celula)

    def falso(story, nome_arquivo):
        for item in story:
            coletar(item)
        return original(story, nome_arquivo)

    monkeypatch.setattr(appmodule, '_pdf_response', falso)
    return resultado


def registrar(client, email='pdf@escritorio.com'):
    resp = client.post('/api/escritorio/registro', json={'nome': 'Escritorio PDF', 'email': email, 'senha': 'SenhaSegura123'})
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
    adv = client.post('/api/escritorio/advogados', json={'nome': 'Dra. PDF', 'telefone_oficial': '61911116666'},
                      headers=he).get_json()['id']
    proc = client.post('/api/escritorio/processos', json={
        'advogado_id': adv, 'cliente_nome': 'Cliente PDF', 'cliente_telefone': '61955556666',
        'numero_processo': '0001234-56.2026.8.07.0001', 'descricao': 'Ação de cobrança',
    }, headers=he).get_json()
    return {'he': he, 'adv': adv, 'proc': proc}


def gravar_tentativa(processo_id, descricao, numero_suspeito, canal='whatsapp'):
    """Grava direto no banco, como um registro legado ou vindo de rota pública."""
    with appmodule.app.app_context():
        tentativa = appmodule.TentativaContato(
            processo_id=processo_id, descricao=descricao, numero_suspeito=numero_suspeito, canal=canal)
        appmodule.db.session.add(tentativa)
        appmodule.db.session.commit()
        return tentativa.id


def assert_pdf_valido(resp):
    assert resp.status_code == 200, resp.get_data(as_text=True)[:300]
    assert resp.mimetype == 'application/pdf'
    assert resp.data.startswith(b'%PDF-') and b'%%EOF' in resp.data[-1024:]


# ---------- texto legítimo ----------

def test_texto_normal_continua_aparecendo(client, cenario, capturado):
    tid = gravar_tentativa(cenario['proc']['id'], 'Pediu Pix para liberar alvará', '61999998888')
    assert_pdf_valido(client.get(f'/api/escritorio/relatorio/tentativa/{tid}/pdf', headers=cenario['he']))
    textos = capturado['textos']
    for esperado in ('Escritorio PDF', 'Dra. PDF', 'Cliente PDF', 'Pediu Pix para liberar alvará',
                     '61999998888', '0001234-56.2026.8.07.0001', 'Relatório de Tentativa Suspeita', 'Escritório'):
        assert esperado in textos, esperado
    assert capturado['links'] == [] and capturado['imagens'] == []


def test_caracteres_especiais_aparecem_literalmente(client, cenario, capturado):
    tid = gravar_tentativa(cenario['proc']['id'], ESPECIAIS, '61900000000')
    assert_pdf_valido(client.get(f'/api/escritorio/relatorio/tentativa/{tid}/pdf', headers=cenario['he']))
    assert ESPECIAIS in capturado['textos']
    assert '&amp; &#x41; &bogus;' not in capturado['textos']  # só aparece se veio do usuário


# ---------- marcação maliciosa ----------

@pytest.mark.parametrize('payload', MALICIOSOS)
def test_descricao_maliciosa_vira_texto_no_relatorio_de_tentativa(client, cenario, capturado, sem_rede, payload):
    tid = gravar_tentativa(cenario['proc']['id'], payload, '61900000000')
    assert_pdf_valido(client.get(f'/api/escritorio/relatorio/tentativa/{tid}/pdf', headers=cenario['he']))
    assert payload in capturado['textos']  # exibido exatamente como foi digitado
    assert capturado['links'] == [] and capturado['imagens'] == []
    assert sem_rede == []


@pytest.mark.parametrize('payload', [IMG_URL[:20], '<a href=x>1</a>', '<b>9', '&<>'])
def test_numero_suspeito_malicioso_nao_quebra_relatorios(client, cenario, capturado, sem_rede, payload):
    tid = gravar_tentativa(cenario['proc']['id'], 'ok', payload, canal='<img src=x>')
    he = cenario['he']
    assert_pdf_valido(client.get(f'/api/escritorio/relatorio/tentativa/{tid}/pdf', headers=he))
    assert_pdf_valido(client.get(f"/api/escritorio/relatorio/processo/{cenario['proc']['id']}/pdf", headers=he))
    assert_pdf_valido(client.get('/api/escritorio/relatorio/mensal/pdf', headers=he))
    assert payload in capturado['textos'] and '<img src=x>' in capturado['textos']
    assert capturado['links'] == [] and capturado['imagens'] == []
    assert sem_rede == []


def test_descricao_publica_maliciosa_nao_quebra_relatorio(client, cenario, capturado, sem_rede):
    resp = client.post('/api/publico/verificar', json={
        'codigo': cenario['proc']['codigo_unico'], 'numero': '61900000000', 'descricao': IMG_URL + LINK + SCRIPT})
    assert resp.status_code == 200
    with appmodule.app.app_context():
        tid = appmodule.TentativaContato.query.one().id
    assert_pdf_valido(client.get(f'/api/escritorio/relatorio/tentativa/{tid}/pdf', headers=cenario['he']))
    assert IMG_URL + LINK + SCRIPT in capturado['textos']
    assert capturado['links'] == [] and capturado['imagens'] == [] and sem_rede == []


def test_observacao_e_descricao_do_processo_maliciosas(client, cenario, capturado, sem_rede):
    he = cenario['he']
    client.put(f"/api/escritorio/processos/{cenario['proc']['id']}", json={'descricao': LINK + '<b>'}, headers=he)
    cca = client.post('/api/escritorio/contato-seguro/iniciar', json={
        'advogado_id': cenario['adv'], 'processo_id': cenario['proc']['id'], 'observacao': IMG_URL}, headers=he).get_json()
    assert_pdf_valido(client.get(f"/api/escritorio/relatorio/contato-seguro/{cca['id']}/pdf", headers=he))
    assert_pdf_valido(client.get(f"/api/escritorio/relatorio/processo/{cenario['proc']['id']}/pdf", headers=he))
    assert IMG_URL in capturado['textos'] and LINK + '<b>' in capturado['textos']
    assert capturado['links'] == [] and capturado['imagens'] == [] and sem_rede == []


def test_nomes_maliciosos_de_advogado_e_escritorio(client, cenario, capturado, sem_rede):
    he = cenario['he']
    client.put(f"/api/escritorio/advogados/{cenario['adv']}", json={'nome': '<font size="90">Dr</font> <b>'}, headers=he)
    with appmodule.app.app_context():
        escritorio = appmodule.Escritorio.query.filter_by(email='pdf@escritorio.com').one()
        escritorio.nome = 'Esc <a href="http://x">ltda</a> & cia'
        appmodule.db.session.commit()
    tid = gravar_tentativa(cenario['proc']['id'], 'ok', '61900000000')
    assert_pdf_valido(client.get(f'/api/escritorio/relatorio/tentativa/{tid}/pdf', headers=he))
    assert_pdf_valido(client.get('/api/escritorio/relatorio/mensal/pdf', headers=he))
    assert '<font size="90">Dr</font> <b>' in capturado['textos']
    assert 'Esc <a href="http://x">ltda</a> & cia' in capturado['textos']
    assert capturado['links'] == []


# ---------- marcação do próprio sistema ----------

def test_marcacao_do_sistema_continua_funcionando():
    with appmodule.app.app_context():
        tabela = appmodule._tabela_chave_valor([('Campo', 'Valor')])
    rotulo = tabela._cellvalues[0][0]
    assert ''.join(f.text for f in rotulo.frags) == 'Campo'
    assert all(getattr(f, 'bold', 0) for f in rotulo.frags)  # <b> interno preservado
    assert tabela._cellvalues[0][1].text == 'Valor'


def test_valor_vazio_continua_como_traco():
    with appmodule.app.app_context():
        tabela = appmodule._tabela_chave_valor([('Campo', ''), ('Zero', 0), ('Nada', None)])
    assert [linha[1].text for linha in tabela._cellvalues] == ['—', '—', '—']
