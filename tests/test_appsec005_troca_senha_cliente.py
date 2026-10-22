# -*- coding: utf-8 -*-
"""APPSEC-005: a senha que o escritório entrega é temporária; o titular cria a senha pessoal.

Enquanto clientes.troca_senha_obrigatoria = TRUE o cliente só consegue trocar a senha.
Só a troca feita pelo próprio titular autenticado torna a credencial definitiva; gerar ou
concluir um link de novo acesso (entregue pelo escritório) mantém a troca obrigatória.
"""
import logging

from sqlalchemy import text

from conftest import appmodule, criar_vinculo_legado

TELEFONE = '61966665555'
NOVA_SENHA = 'MinhaSenhaPessoal2026'
ROTAS_BLOQUEADAS = [
    ('get', '/api/cliente/processos', None),
    ('get', '/api/cliente/contato-seguro/ativo', None),
    ('post', '/api/cliente/contato-seguro/verificar', {}),
    ('post', '/api/cliente/contato-seguro/registrar-suspeita', {}),
    ('post', '/api/cliente/verificar', {'numero': '61900000000'}),
    ('post', '/api/cliente/autorizar-escritorio', {'email_escritorio': 'x@x.com'}),
    ('get', '/api/cliente/privacidade/exportar', None),
    ('get', '/api/cliente/privacidade/solicitacoes', None),
]


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


def montar(client, email='titular@esc-a.com', telefone=TELEFONE):
    he = registrar(client, email)
    adv = client.post('/api/escritorio/advogados', json={
        'nome': 'Dra. Troca', 'telefone_oficial': '61911114444'
    }, headers=he).get_json()['id']
    proc = client.post('/api/escritorio/processos', json={
        'advogado_id': adv, 'cliente_nome': 'Cliente Troca', 'cliente_telefone': telefone
    }, headers=he).get_json()
    return he, adv, proc


def login(client, senha, telefone=TELEFONE):
    return client.post('/api/cliente/login', json={'telefone': telefone, 'senha': senha})


def bearer(resp):
    return {'Authorization': f"Bearer {resp.get_json()['token']}"}


def trocar(client, headers, atual, nova=NOVA_SENHA):
    return client.post('/api/cliente/senha', json={'senha_atual': atual, 'nova_senha': nova}, headers=headers)


def flag(telefone=TELEFONE):
    with appmodule.app.app_context():
        return appmodule.Cliente.query.filter_by(telefone=telefone).one().troca_senha_obrigatoria


def chamar(client, metodo, rota, corpo, headers):
    if metodo == 'get':
        return client.get(rota, headers=headers)
    return client.post(rota, json=corpo, headers=headers)


# ---------- estado inicial ----------

def test_cliente_existente_recebe_troca_obrigatoria_na_migracao(client):
    with appmodule.app.app_context():
        appmodule.db.drop_all()
        with appmodule.db.engine.begin() as con:
            con.execute(text(
                'CREATE TABLE clientes (id INTEGER PRIMARY KEY, nome VARCHAR(200) NOT NULL, '
                'telefone VARCHAR(20) NOT NULL, senha_hash VARCHAR(200) NOT NULL, '
                'ativo BOOLEAN NOT NULL DEFAULT 1)'
            ))
            con.execute(text("INSERT INTO clientes (nome, telefone, senha_hash) VALUES ('Legado', '61900000001', 'x')"))
        appmodule._garantir_colunas_novas()
        with appmodule.db.engine.connect() as con:
            assert con.execute(text('SELECT troca_senha_obrigatoria FROM clientes')).scalar() in (1, True)
        # executar de novo não falha (idempotente)
        appmodule._garantir_colunas_novas()


def test_cliente_novo_nasce_com_troca_obrigatoria(client):
    _, _, proc = montar(client)
    assert proc['senha_temporaria']
    assert flag() is True
    resp = login(client, proc['senha_temporaria'])
    assert resp.status_code == 200
    assert resp.get_json()['troca_senha_obrigatoria'] is True


def test_cliente_criado_pelo_orm_sem_informar_tambem_nasce_true(client):
    with appmodule.app.app_context():
        cliente = appmodule.Cliente(nome='ORM', telefone='61900000002', senha_hash='x')
        appmodule.db.session.add(cliente)
        appmodule.db.session.commit()
        assert cliente.troca_senha_obrigatoria is True


# ---------- restrição enquanto TRUE ----------

def test_senha_temporaria_so_permite_iniciar_a_troca(client):
    _, _, proc = montar(client)
    hc = bearer(login(client, proc['senha_temporaria']))
    for metodo, rota, corpo in ROTAS_BLOQUEADAS:
        resp = chamar(client, metodo, rota, corpo, hc)
        assert resp.status_code == 403, rota
        assert resp.get_json()['troca_senha_obrigatoria'] is True, rota
    csrf = client.get_cookie(appmodule.CSRF_COOKIE_NAME).value  # logout por cookie exige CSRF
    assert client.post('/api/logout', headers={'X-CSRF-Token': csrf}).status_code == 200


def test_restricao_vale_tambem_para_sessao_por_cookie(client):
    _, _, proc = montar(client)
    login(client, proc['senha_temporaria'])  # define os cookies HttpOnly + CSRF
    resp = client.get('/api/cliente/processos')
    assert resp.status_code == 403 and resp.get_json()['troca_senha_obrigatoria'] is True


# ---------- troca pelo titular ----------

def test_troca_correta_libera_o_cliente_e_invalida_a_temporaria(client):
    _, _, proc = montar(client)
    temporaria = proc['senha_temporaria']
    hc_antiga = bearer(login(client, temporaria))

    resp = trocar(client, hc_antiga, temporaria)
    assert resp.status_code == 200, resp.get_json()
    assert flag() is False

    # sessão antiga invalidada pelo cv
    assert client.get('/api/cliente/processos', headers=hc_antiga).status_code == 401
    # temporária não funciona mais; a nova funciona e libera a área
    assert login(client, temporaria).status_code == 401
    nova = login(client, NOVA_SENHA)
    assert nova.status_code == 200
    assert nova.get_json()['troca_senha_obrigatoria'] is False
    assert client.get('/api/cliente/processos', headers=bearer(nova)).status_code == 200


def test_troca_recusada_mantem_obrigatoriedade(client):
    _, _, proc = montar(client)
    temporaria = proc['senha_temporaria']
    hc = bearer(login(client, temporaria))
    assert trocar(client, hc, 'senha-errada').status_code == 401
    assert trocar(client, hc, temporaria, nova='curta').status_code == 400
    mesma = 'MesmaSenha12345'
    with appmodule.app.app_context():
        cliente = appmodule.Cliente.query.filter_by(telefone=TELEFONE).one()
        cliente.senha_hash = appmodule.hash_senha(mesma)
        appmodule.db.session.commit()
    hc = bearer(login(client, mesma))
    assert trocar(client, hc, mesma, nova=mesma).status_code == 400
    assert flag() is True


def test_cliente_ja_liberado_continua_com_login_e_acesso_normais(client):
    _, _, proc = montar(client)
    hc = bearer(login(client, proc['senha_temporaria']))
    trocar(client, hc, proc['senha_temporaria'])
    hc = bearer(login(client, NOVA_SENHA))
    for metodo, rota, corpo in ROTAS_BLOQUEADAS[:3] + ROTAS_BLOQUEADAS[6:]:
        assert chamar(client, metodo, rota, corpo, hc).status_code == 200, rota


# ---------- escritório e novo acesso ----------

def test_escritorio_nunca_recebe_a_senha_nova(client):
    he, _, proc = montar(client)
    hc = bearer(login(client, proc['senha_temporaria']))
    trocar(client, hc, proc['senha_temporaria'])

    respostas = [
        client.get('/api/escritorio/clientes', headers=he),
        client.get('/api/escritorio/processos', headers=he),
        client.post(f"/api/escritorio/cliente/{proc['cliente_id']}/link-reset", headers=he),
        client.get('/api/escritorio/privacidade/exportar', headers=he),
        client.get('/escritorio/clientes'),
        client.get('/escritorio/processos'),
    ]
    for resp in respostas:
        assert NOVA_SENHA not in resp.get_data(as_text=True)
    with appmodule.app.app_context():
        cliente = appmodule.Cliente.query.filter_by(telefone=TELEFONE).one()
        assert NOVA_SENHA not in cliente.senha_hash
        assert appmodule.verificar_senha(cliente.senha_hash, NOVA_SENHA)


def test_gerar_novo_acesso_nao_marca_credencial_como_definitiva(client):
    he, _, proc = montar(client)
    link = client.post(f"/api/escritorio/cliente/{proc['cliente_id']}/link-reset", headers=he).get_json()['link']
    assert flag() is True  # gerar o link não muda nada

    token = link.split('token=', 1)[1]
    resp = client.post('/api/cliente/redefinir-senha', json={'token': token, 'nova_senha': 'SenhaDoLink2026'})
    assert resp.status_code == 200
    assert flag() is True  # concluir o link entregue pelo escritório também não

    entrada = login(client, 'SenhaDoLink2026')
    assert entrada.status_code == 200 and entrada.get_json()['troca_senha_obrigatoria'] is True
    assert client.get('/api/cliente/processos', headers=bearer(entrada)).status_code == 403


def test_novo_acesso_apos_senha_pessoal_volta_a_exigir_troca(client):
    he, _, proc = montar(client)
    hc = bearer(login(client, proc['senha_temporaria']))
    trocar(client, hc, proc['senha_temporaria'])
    assert flag() is False

    link = client.post(f"/api/escritorio/cliente/{proc['cliente_id']}/link-reset", headers=he).get_json()['link']
    assert flag() is False  # só gerar não altera a senha nem o estado
    assert login(client, NOVA_SENHA).status_code == 200

    client.post('/api/cliente/redefinir-senha', json={'token': link.split('token=', 1)[1], 'nova_senha': 'OutraDoLink2026'})
    assert flag() is True


def test_cliente_compartilhado_nao_pode_ter_senha_redefinida_por_um_escritorio(client):
    _, _, proc = montar(client)
    hb = registrar(client, 'outro@esc-b.com')
    adv_b = client.post('/api/escritorio/advogados', json={
        'nome': 'Dr. B', 'telefone_oficial': '61922225555'
    }, headers=hb).get_json()['id']
    criar_vinculo_legado(adv_b, TELEFONE)
    with appmodule.app.app_context():
        hash_antes = appmodule.Cliente.query.filter_by(telefone=TELEFONE).one().senha_hash

    resp = client.post(f"/api/escritorio/cliente/{proc['cliente_id']}/link-reset", headers=hb)
    assert resp.status_code == 409
    assert 'link' not in resp.get_json()
    with appmodule.app.app_context():
        cliente = appmodule.Cliente.query.filter_by(telefone=TELEFONE).one()
        assert cliente.senha_hash == hash_antes and cliente.reset_token is None


# ---------- recuperação, RR2, logs ----------

def test_esqueci_senha_continua_generico(client):
    montar(client)
    existe = client.post('/api/cliente/esqueci-senha', json={'telefone': TELEFONE}).get_json()
    nao_existe = client.post('/api/cliente/esqueci-senha', json={'telefone': '61900009999'}).get_json()
    assert existe == nao_existe
    assert flag() is True


def test_rr2_continua_funcionando_depois_da_troca(client):
    _, _, proc = montar(client)
    registrar(client, 'novo@esc-b.com')
    hc = bearer(login(client, proc['senha_temporaria']))
    assert client.post('/api/cliente/autorizar-escritorio', json={
        'email_escritorio': 'novo@esc-b.com', 'confirmar': True}, headers=hc).status_code == 403
    trocar(client, hc, proc['senha_temporaria'])
    hc = bearer(login(client, NOVA_SENHA))
    resp = client.post('/api/cliente/autorizar-escritorio', json={
        'email_escritorio': 'novo@esc-b.com', 'confirmar': True}, headers=hc)
    assert resp.status_code == 200 and resp.get_json()['codigo']


def test_nenhuma_senha_aparece_em_log(client, caplog):
    caplog.set_level(logging.DEBUG)
    he, _, proc = montar(client)
    temporaria = proc['senha_temporaria']
    hc = bearer(login(client, temporaria))
    client.get('/api/cliente/processos', headers=hc)
    trocar(client, hc, 'errada')
    trocar(client, hc, temporaria)
    login(client, NOVA_SENHA)
    login(client, temporaria)
    texto = caplog.text + ''.join(str(r.args) for r in caplog.records)
    assert temporaria not in texto
    assert NOVA_SENHA not in texto


def test_area_do_cliente_tem_modo_de_troca_obrigatoria():
    html = appmodule.app.test_client().get('/cliente/area').get_data(as_text=True)
    assert 'id="painelSenhaCliente"' in html and 'id="avisoTrocaSenha"' in html
    assert 'troca_senha_obrigatoria' in html
    login_html = appmodule.app.test_client().get('/cliente/login').get_data(as_text=True)
    assert 'troca_senha_obrigatoria' in login_html
