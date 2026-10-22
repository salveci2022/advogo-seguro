# -*- coding: utf-8 -*-
"""R1: um escritório nunca recebe nome ou e-mail de cliente cadastrado por outro escritório.

O cadastro do cliente é global (telefone único). Desde o RR2 a API não cria mais
vínculo entre escritórios; os vínculos legados são montados direto no banco de
teste e B continua vendo só o telefone, nunca o nome ou o e-mail de A.
"""
from conftest import appmodule, criar_vinculo_legado

TELEFONE = '61988880001'
NOME_REAL = 'Maria Titular da Silva'
EMAIL_REAL = 'maria.titular@cliente-a.com'


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


def criar_advogado(client, headers, telefone_oficial):
    adv = client.post('/api/escritorio/advogados', json={
        'nome': 'Dra. Responsavel', 'telefone_oficial': telefone_oficial
    }, headers=headers)
    assert adv.status_code == 200, adv.get_json()
    return adv.get_json()['id']


def criar_processo(client, headers, advogado_id, nome, telefone, email=''):
    resp = client.post('/api/escritorio/processos', json={
        'advogado_id': advogado_id, 'cliente_nome': nome,
        'cliente_telefone': telefone, 'cliente_email': email,
    }, headers=headers)
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()


def cenario_dois_escritorios(client):
    ha = registrar(client, 'titular@escritorio-a.com')
    adv_a = criar_advogado(client, ha, '61911110000')
    proc_a = criar_processo(client, ha, adv_a, NOME_REAL, TELEFONE, EMAIL_REAL)

    hb = registrar(client, 'outro@escritorio-b.com')
    adv_b = criar_advogado(client, hb, '61922220000')
    proc_b = criar_vinculo_legado(adv_b, TELEFONE)
    return ha, hb, proc_a, proc_b, adv_b


def sem_dados_do_titular(texto):
    return NOME_REAL not in texto and EMAIL_REAL not in texto


def textos_do_pdf(monkeypatch):
    """Captura o texto das tabelas do PDF antes da renderização."""
    capturado = []
    original = appmodule._pdf_response

    def coletar(item):
        if hasattr(item, 'text'):
            capturado.append(str(item.text))
        for linha in getattr(item, '_cellvalues', []) or []:
            for celula in linha:
                coletar(celula) if not isinstance(celula, str) else capturado.append(celula)

    def falso(story, nome_arquivo):
        for item in story:
            coletar(item)
        return original(story, nome_arquivo)

    monkeypatch.setattr(appmodule, '_pdf_response', falso)
    return capturado


# ---------- Exposição bloqueada ----------

def test_criar_processo_com_telefone_de_outro_escritorio_nao_revela_nome(client):
    cenario_dois_escritorios(client)
    hc = registrar(client, 'terceiro@escritorio-c.com')
    adv_c = criar_advogado(client, hc, '61944440000')

    resp = client.post('/api/escritorio/processos', json={
        'advogado_id': adv_c, 'cliente_nome': 'Nome digitado por C', 'cliente_telefone': TELEFONE,
    }, headers=hc)
    assert resp.status_code == 409
    assert sem_dados_do_titular(resp.get_data(as_text=True))


def test_listas_do_outro_escritorio_nao_expoem_nome_nem_email(client):
    _, hb, _, proc_b, adv_b = cenario_dois_escritorios(client)

    cca = client.post('/api/escritorio/contato-seguro/iniciar', json={
        'advogado_id': adv_b, 'processo_id': proc_b['id'], 'canal': 'whatsapp'
    }, headers=hb)
    assert cca.status_code == 200, cca.get_json()
    verificacao = client.post('/api/publico/verificar', json={
        'codigo': proc_b['codigo_unico'], 'numero': '61900000000', 'canal': 'whatsapp'
    })
    assert verificacao.status_code == 200, verificacao.get_json()

    for rota in ('/api/escritorio/clientes', '/api/escritorio/processos',
                 '/api/escritorio/tentativas', '/api/escritorio/contato-seguro/listar'):
        resp = client.get(rota, headers=hb)
        assert resp.status_code == 200, (rota, resp.get_json())
        assert sem_dados_do_titular(resp.get_data(as_text=True)), rota

    clientes = client.get('/api/escritorio/clientes', headers=hb).get_json()
    assert clientes[0]['telefone'] == TELEFONE
    assert clientes[0]['email'] is None
    assert len(client.get('/api/escritorio/tentativas', headers=hb).get_json()) == 1


def test_relatorios_pdf_do_outro_escritorio_nao_expoem_nome(client, monkeypatch):
    _, hb, _, proc_b, adv_b = cenario_dois_escritorios(client)
    cca = client.post('/api/escritorio/contato-seguro/iniciar', json={
        'advogado_id': adv_b, 'processo_id': proc_b['id'], 'canal': 'whatsapp'
    }, headers=hb).get_json()
    client.post('/api/publico/verificar', json={
        'codigo': proc_b['codigo_unico'], 'numero': '61900000000', 'canal': 'whatsapp'
    })
    tentativa_id = client.get('/api/escritorio/tentativas', headers=hb).get_json()[0]['id']

    textos = textos_do_pdf(monkeypatch)
    for rota in (f"/api/escritorio/relatorio/processo/{proc_b['id']}/pdf",
                 f"/api/escritorio/relatorio/contato-seguro/{cca['id']}/pdf",
                 f'/api/escritorio/relatorio/tentativa/{tentativa_id}/pdf',
                 '/api/escritorio/relatorio/mensal/pdf'):
        resp = client.get(rota, headers=hb)
        assert resp.status_code == 200, rota
        assert resp.mimetype == 'application/pdf'
    assert textos, 'nenhum texto capturado dos PDFs'
    assert sem_dados_do_titular(' '.join(textos))


# ---------- Fluxo legítimo preservado ----------

def test_escritorio_titular_continua_vendo_dados_completos(client):
    ha, _, _, _, _ = cenario_dois_escritorios(client)

    clientes = client.get('/api/escritorio/clientes', headers=ha).get_json()
    assert clientes[0]['nome'] == NOME_REAL
    assert clientes[0]['email'] == EMAIL_REAL
    processos = client.get('/api/escritorio/processos', headers=ha).get_json()
    assert processos[0]['cliente_nome'] == NOME_REAL


def test_cliente_do_proprio_escritorio_sem_compartilhamento_aparece_normalmente(client):
    ha = registrar(client, 'unico@escritorio-a.com')
    adv = criar_advogado(client, ha, '61933330000')
    novo = criar_processo(client, ha, adv, 'Joao Proprio', '61988880002', 'joao@proprio.com')
    assert novo['cliente_nome'] == 'Joao Proprio'
    assert novo['cliente_existente'] is False
    assert novo['senha_temporaria']

    segundo = criar_processo(client, ha, adv, 'Joao Proprio', '61988880002')
    assert segundo['cliente_existente'] is True
    assert segundo['cliente_nome'] == 'Joao Proprio'

    clientes = client.get('/api/escritorio/clientes', headers=ha).get_json()
    assert clientes == [dict(clientes[0], nome='Joao Proprio', email='joao@proprio.com', processos_count=2)]


def test_cliente_compartilhado_ve_processos_dos_dois_escritorios(client):
    """O vínculo entre escritórios continua permitido; só a exposição foi bloqueada."""
    cenario_dois_escritorios(client)
    with appmodule.app.app_context():
        cliente = appmodule.Cliente.query.filter_by(telefone=TELEFONE).first()
        assert cliente.nome == NOME_REAL
        assert cliente.email == EMAIL_REAL
        assert appmodule.Processo.query.filter_by(cliente_id=cliente.id).count() == 2
