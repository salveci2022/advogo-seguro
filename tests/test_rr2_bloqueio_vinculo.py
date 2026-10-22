# -*- coding: utf-8 -*-
"""RR2/RR2b: um escritório não consegue se vincular sozinho a cliente atendido por outro.

Cadastro existente só é reutilizado pelo escritório que já tem processo com o
cliente. Qualquer outro caso (cliente de outro escritório ou cadastro sem
processos) responde 409 sem dados pessoais e sem criar vínculo.
"""
from conftest import appmodule, cliente_ja_criou_senha_pessoal, criar_vinculo_legado

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


def criar_advogado(client, headers, telefone_oficial, nome='Dra. Responsavel'):
    resp = client.post('/api/escritorio/advogados', json={
        'nome': nome, 'telefone_oficial': telefone_oficial
    }, headers=headers)
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()['id']


def post_processo(client, headers, advogado_id, telefone, nome='Nome digitado', email=''):
    return client.post('/api/escritorio/processos', json={
        'advogado_id': advogado_id, 'cliente_nome': nome,
        'cliente_telefone': telefone, 'cliente_email': email,
    }, headers=headers)


def cenario(client):
    ha = registrar(client, 'titular@escritorio-a.com')
    adv_a = criar_advogado(client, ha, '61911110000')
    proc_a = post_processo(client, ha, adv_a, TELEFONE, NOME_REAL, EMAIL_REAL)
    assert proc_a.status_code == 200, proc_a.get_json()
    hb = registrar(client, 'outro@escritorio-b.com')
    adv_b = criar_advogado(client, hb, '61922220000', 'Dr. Intruso')
    return ha, hb, proc_a.get_json(), adv_a, adv_b


def contagens(cliente_id):
    with appmodule.app.app_context():
        processos = appmodule.Processo.query.filter_by(cliente_id=cliente_id).all()
        return len(processos), {p.escritorio_id for p in processos}


def processos_na_area_do_cliente(client, senha):
    client.delete_cookie(appmodule.AUTH_COOKIE_NAME)
    cliente_ja_criou_senha_pessoal(TELEFONE)
    login = client.post('/api/cliente/login', json={'telefone': TELEFONE, 'senha': senha})
    assert login.status_code == 200, login.get_json()
    token = login.get_json()['token']
    return client.get('/api/cliente/processos', headers={'Authorization': f'Bearer {token}'}).get_json()


# ---------- Dois escritórios: vínculo bloqueado ----------

def test_outro_escritorio_nao_vincula_cliente_existente(client):
    _, hb, proc_a, _, adv_b = cenario(client)
    antes = contagens(proc_a['cliente_id'])

    resp = post_processo(client, hb, adv_b, TELEFONE)

    assert resp.status_code == 409
    dados = resp.get_json()
    assert dados['vinculo_bloqueado'] is True
    assert set(dados) == {'erro', 'vinculo_bloqueado'}
    texto = resp.get_data(as_text=True)
    assert NOME_REAL not in texto and EMAIL_REAL not in texto
    assert contagens(proc_a['cliente_id']) == antes
    assert client.get('/api/escritorio/clientes', headers=hb).get_json() == []
    assert client.get('/api/escritorio/processos', headers=hb).get_json() == []


def test_telefone_com_mascara_tambem_e_bloqueado(client):
    _, hb, proc_a, _, adv_b = cenario(client)
    resp = post_processo(client, hb, adv_b, '(61) 98888-0001')
    assert resp.status_code == 409
    assert contagens(proc_a['cliente_id'])[0] == 1


def test_cliente_nao_ve_processo_nem_advogado_do_escritorio_bloqueado(client):
    _, hb, proc_a, _, adv_b = cenario(client)
    post_processo(client, hb, adv_b, TELEFONE)

    processos = processos_na_area_do_cliente(client, proc_a['senha_temporaria'])
    assert [p['id'] for p in processos] == [proc_a['id']]
    assert 'Dr. Intruso' not in str(processos)


def test_tentativas_repetidas_de_vinculo_sao_limitadas(client):
    _, hb, _, _, adv_b = cenario(client)
    codigos = [post_processo(client, hb, adv_b, TELEFONE).status_code for _ in range(6)]
    assert codigos == [409] * 5 + [429]


# ---------- Fluxo legítimo do próprio escritório ----------

def test_titular_reutiliza_o_proprio_cliente_normalmente(client):
    ha, _, proc_a, adv_a, _ = cenario(client)

    segundo = post_processo(client, ha, adv_a, TELEFONE)
    assert segundo.status_code == 200, segundo.get_json()
    dados = segundo.get_json()
    assert dados['cliente_id'] == proc_a['cliente_id']
    assert dados['cliente_existente'] is True
    assert dados['cliente_nome'] == NOME_REAL
    assert dados['senha_temporaria'] is None


def test_cliente_novo_continua_sendo_criado(client):
    _, hb, _, _, adv_b = cenario(client)
    novo = post_processo(client, hb, adv_b, '61977770000', 'Cliente Novo de B')
    assert novo.status_code == 200, novo.get_json()
    assert novo.get_json()['cliente_existente'] is False
    assert novo.get_json()['senha_temporaria']


# ---------- Titularidade e exclusão de processos ----------

def test_cadastro_sem_processos_nao_pode_ser_assumido_por_outro_escritorio(client):
    ha, hb, proc_a, _, adv_b = cenario(client)
    assert client.delete(f"/api/escritorio/processos/{proc_a['id']}", headers=ha).status_code == 200

    resp = post_processo(client, hb, adv_b, TELEFONE)

    assert resp.status_code == 409
    assert NOME_REAL not in resp.get_data(as_text=True)
    assert contagens(proc_a['cliente_id']) == (0, set())


def test_titular_que_excluiu_todos_os_processos_tambem_precisa_do_suporte(client):
    """Limitação documentada: sem coluna de titular, o cadastro órfão fica bloqueado para todos."""
    ha, _, proc_a, adv_a, _ = cenario(client)
    client.delete(f"/api/escritorio/processos/{proc_a['id']}", headers=ha)
    assert post_processo(client, ha, adv_a, TELEFONE).status_code == 409


def test_exclusao_pelo_titular_com_vinculo_legado_nao_entrega_dados_a_outro_por_api(client):
    ha, hb, proc_a, _, adv_b = cenario(client)
    criar_vinculo_legado(adv_b, TELEFONE)

    novo = post_processo(client, hb, adv_b, TELEFONE)
    assert novo.status_code == 200  # B já tem processo legado com o cliente
    assert novo.get_json()['cliente_nome'] != NOME_REAL
    assert client.get('/api/escritorio/clientes', headers=hb).get_json()[0]['email'] is None


def test_exclusao_do_proprio_processo_por_b_nao_afeta_titular(client):
    ha, hb, proc_a, _, adv_b = cenario(client)
    legado = criar_vinculo_legado(adv_b, TELEFONE)
    assert client.delete(f"/api/escritorio/processos/{legado['id']}", headers=hb).status_code == 200
    assert contagens(proc_a['cliente_id']) == (1, {contagens(proc_a['cliente_id'])[1].pop()})
    clientes_a = client.get('/api/escritorio/clientes', headers=ha).get_json()
    assert clientes_a[0]['nome'] == NOME_REAL and clientes_a[0]['email'] == EMAIL_REAL


# ---------- Autenticação e permissões ----------

def test_criacao_de_processo_exige_autenticacao(client):
    cenario(client)
    client.delete_cookie(appmodule.AUTH_COOKIE_NAME)
    resp = client.post('/api/escritorio/processos', json={
        'advogado_id': 1, 'cliente_nome': 'x', 'cliente_telefone': TELEFONE
    })
    assert resp.status_code == 401


def test_cliente_nao_cria_processo_com_token_de_cliente(client):
    _, _, proc_a, _, adv_b = cenario(client)
    client.delete_cookie(appmodule.AUTH_COOKIE_NAME)
    login = client.post('/api/cliente/login', json={'telefone': TELEFONE, 'senha': proc_a['senha_temporaria']})
    headers = {'Authorization': f"Bearer {login.get_json()['token']}"}
    assert post_processo(client, headers, adv_b, '61977770001').status_code == 401


def test_outro_escritorio_continua_sem_acesso_aos_processos_do_titular(client):
    _, hb, proc_a, _, adv_b = cenario(client)
    pid = proc_a['id']
    assert client.put(f'/api/escritorio/processos/{pid}', json={'descricao': 'x'}, headers=hb).status_code == 404
    assert client.delete(f'/api/escritorio/processos/{pid}', headers=hb).status_code == 404
    assert client.get(f'/api/escritorio/relatorio/processo/{pid}/pdf', headers=hb).status_code == 404
    assert client.post('/api/escritorio/contato-seguro/iniciar', json={
        'advogado_id': adv_b, 'cliente_id': proc_a['cliente_id']
    }, headers=hb).status_code == 403
    assert client.post(f"/api/escritorio/cliente/{proc_a['cliente_id']}/link-reset", headers=hb).status_code == 404
