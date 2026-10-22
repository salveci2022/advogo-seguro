# -*- coding: utf-8 -*-
"""APPSEC-011: respostas públicas não revelam se e-mail, telefone ou cadastro existem.

Cobre status, texto, formato do JSON e custo (hash calculado também para conta inexistente;
e-mail enviado fora da requisição). Os testes "em produção" simulam IS_PRODUCTION, sem rede.
"""
import threading
import time

import pytest

from conftest import appmodule

SENHA = 'SenhaSegura123'
CNPJ = '11222333000181'
OUTRO_CNPJ = '45723174000110'


def registrar_escritorio(client, email='existe@esc.com', cnpj=CNPJ):
    resp = client.post('/api/escritorio/registro', json={'nome': 'Esc Existe', 'email': email, 'senha': SENHA, 'cnpj': cnpj})
    assert resp.status_code == 200, resp.get_json()


def cadastro_pendente(client, email='pendente@esc.com'):
    resp = client.post('/api/comercial/registro', json={
        'nome': 'Esc Pendente', 'email': email, 'senha': SENHA, 'tipo_pessoa': 'PJ', 'cnpj': CNPJ, 'plano': 'escritorio'})
    assert resp.status_code == 201, resp.get_json()
    return resp.get_json()


def criar_cliente(client, telefone='61944443333'):
    he = client.post('/api/escritorio/registro', json={'nome': 'Esc C', 'email': 'c@esc.com', 'senha': SENHA}).get_json()
    he = {'Authorization': f"Bearer {he['token']}"}
    with appmodule.app.app_context():
        e = appmodule.Escritorio.query.filter_by(email='c@esc.com').one()
        e.plano, e.plano_expira = 'profissional', None
        appmodule.db.session.commit()
    adv = client.post('/api/escritorio/advogados', json={'nome': 'Dra', 'telefone_oficial': '61911110000'}, headers=he).get_json()['id']
    proc = client.post('/api/escritorio/processos', json={
        'advogado_id': adv, 'cliente_nome': 'Cliente', 'cliente_telefone': telefone}, headers=he).get_json()
    return proc['senha_temporaria']


def publico(resp):
    """O que um atacante anônimo observa: status, chaves e corpo."""
    return resp.status_code, sorted((resp.get_json() or {}).keys()), resp.get_json()


@pytest.fixture()
def producao(monkeypatch):
    """Simula produção com SMTP configurado; o envio real é substituído por um espião."""
    enviados = []
    monkeypatch.setattr(appmodule, 'IS_PRODUCTION', True)
    monkeypatch.setattr(appmodule, 'SMTP_HOST', 'smtp.invalid')
    monkeypatch.setattr(appmodule, 'SMTP_FROM', 'nao-responda@advogo.invalid')
    monkeypatch.setattr(appmodule, 'PUBLIC_BASE_URL', 'https://advogo.example')
    monkeypatch.setattr(appmodule, '_enviar_mensagem_smtp', lambda mensagem: enviados.append(mensagem['To']) or True)
    return enviados


@pytest.fixture()
def hash_espiao(monkeypatch):
    chamadas = []
    original = appmodule.verificar_senha

    def espiao(hash_salvo, senha):
        chamadas.append(hash_salvo)
        return original(hash_salvo, senha)

    monkeypatch.setattr(appmodule, 'verificar_senha', espiao)
    return chamadas


# ---------- login ----------

def test_login_escritorio_existente_e_inexistente_respondem_igual(client, hash_espiao):
    registrar_escritorio(client)
    existe = client.post('/api/escritorio/login', json={'email': 'existe@esc.com', 'senha': 'errada'})
    nao_existe = client.post('/api/escritorio/login', json={'email': 'naoexiste@esc.com', 'senha': 'errada'})
    assert publico(existe) == publico(nao_existe) == (401, ['erro'], {'erro': 'Email ou senha incorretos'})
    # As duas tentativas calculam um hash PBKDF2 (a inexistente usa o hash fictício).
    assert len(hash_espiao) == 2
    assert hash_espiao[1] == appmodule._HASH_SENHA_FICTICIA
    assert appmodule._HASH_SENHA_FICTICIA.startswith('pbkdf2:sha256')


def test_login_cliente_existente_e_inexistente_respondem_igual(client, hash_espiao):
    criar_cliente(client)
    hash_espiao.clear()
    existe = client.post('/api/cliente/login', json={'telefone': '61944443333', 'senha': 'errada'})
    nao_existe = client.post('/api/cliente/login', json={'telefone': '61900001111', 'senha': 'errada'})
    assert publico(existe) == publico(nao_existe) == (401, ['erro'], {'erro': 'Telefone ou senha incorretos'})
    assert len(hash_espiao) == 2 and hash_espiao[1] == appmodule._HASH_SENHA_FICTICIA


def test_senha_ficticia_nunca_autentica(client):
    assert appmodule._senha_confere(None, '') is False
    assert client.post('/api/escritorio/login', json={'email': 'ninguem@esc.com', 'senha': ''}).status_code == 401


def test_usuario_valido_autentica_e_senha_errada_bloqueia(client):
    registrar_escritorio(client)
    assert client.post('/api/escritorio/login', json={'email': 'existe@esc.com', 'senha': SENHA}).status_code == 200
    assert client.post('/api/escritorio/login', json={'email': 'existe@esc.com', 'senha': 'SenhaErrada99'}).status_code == 401
    senha_cliente = criar_cliente(client)
    assert client.post('/api/cliente/login', json={'telefone': '61944443333', 'senha': senha_cliente}).status_code == 200
    assert client.post('/api/cliente/login', json={'telefone': '61944443333', 'senha': 'SenhaErrada99'}).status_code == 401


def test_rate_limit_de_login_continua_e_e_igual_para_inexistente(client):
    registrar_escritorio(client)
    respostas = {}
    for email in ('existe@esc.com', 'naoexiste@esc.com'):
        status = [client.post('/api/escritorio/login', json={'email': email, 'senha': 'errada'}).status_code
                  for _ in range(appmodule.MAX_TENTATIVAS + 1)]
        assert status == [401] * appmodule.MAX_TENTATIVAS + [429]
        ultima = client.post('/api/escritorio/login', json={'email': email, 'senha': 'errada'})
        respostas[email] = (ultima.status_code, ultima.get_json()['erro'].split(' Tente')[0])
    assert respostas['existe@esc.com'] == respostas['naoexiste@esc.com']


# ---------- recuperação ----------

def test_esqueci_senha_escritorio_igual_em_producao(client, producao):
    registrar_escritorio(client)
    existe = client.post('/api/escritorio/esqueci-senha', json={'email': 'existe@esc.com'})
    nao_existe = client.post('/api/escritorio/esqueci-senha', json={'email': 'naoexiste@esc.com'})
    assert publico(existe) == publico(nao_existe)
    assert existe.status_code == 200 and 'link_dev' not in existe.get_json()
    corpo = existe.get_data(as_text=True)
    assert CNPJ not in corpo and 'cnpj' not in corpo.lower() and 'cpf' not in corpo.lower()
    for _ in range(50):  # envio em segundo plano
        if producao:
            break
        time.sleep(0.02)
    assert producao == ['existe@esc.com']


def test_envio_de_email_nao_atrasa_a_resposta(client, producao, monkeypatch):
    """O SMTP lento não pode deixar a resposta da conta existente mais demorada."""
    registrar_escritorio(client)
    liberar = threading.Event()
    iniciado = threading.Event()

    def smtp_lento(mensagem):
        iniciado.set()
        liberar.wait(5)
        return True

    monkeypatch.setattr(appmodule, '_enviar_mensagem_smtp', smtp_lento)
    resp = client.post('/api/escritorio/esqueci-senha', json={'email': 'existe@esc.com'})
    assert resp.status_code == 200
    assert iniciado.wait(2)          # o envio começou...
    assert not liberar.is_set()      # ...e a resposta saiu antes de ele terminar
    liberar.set()


def test_esqueci_senha_cliente_igual(client):
    criar_cliente(client)
    existe = client.post('/api/cliente/esqueci-senha', json={'telefone': '61944443333'})
    nao_existe = client.post('/api/cliente/esqueci-senha', json={'telefone': '61900001111'})
    assert publico(existe) == publico(nao_existe) and existe.status_code == 200


def test_reenviar_confirmacao_igual_para_pendente_confirmado_e_inexistente(client, producao):
    registrar_escritorio(client, 'confirmado@esc.com', cnpj=OUTRO_CNPJ)  # fluxo legado: já confirmado
    cadastro_pendente(client)
    respostas = [client.post('/api/comercial/reenviar-confirmacao', json={'email': email})
                 for email in ('pendente@esc.com', 'confirmado@esc.com', 'naoexiste@esc.com')]
    assert publico(respostas[0]) == publico(respostas[1]) == publico(respostas[2])
    assert sorted(respostas[0].get_json()) == ['mensagem', 'ok']


# ---------- confirmação de e-mail ----------

def test_confirmacao_de_email_tem_resposta_unica_para_qualquer_falha(client):
    pendente = cadastro_pendente(client)
    registrar_escritorio(client, 'confirmado@esc.com', cnpj=OUTRO_CNPJ)
    expirado = cadastro_pendente(client, 'expirado@esc.com')
    with appmodule.app.app_context():
        e = appmodule.Escritorio.query.filter_by(email='expirado@esc.com').one()
        e.email_confirmacao_expira = appmodule.agora_utc()
        appmodule.db.session.commit()
    errado = '000000' if pendente['codigo_dev'] != '000000' else '111111'
    casos = [('naoexiste@esc.com', '123456'), ('confirmado@esc.com', '123456'),
             ('expirado@esc.com', expirado['codigo_dev']), ('pendente@esc.com', errado)]
    respostas = [publico(client.post('/api/comercial/confirmar-email', json={'email': e, 'codigo': c})) for e, c in casos]
    assert all(r == (400, ['erro'], {'erro': appmodule.MENSAGEM_CONFIRMACAO_INVALIDA}) for r in respostas)


def test_cadastro_legitimo_e_confirmacao_continuam_funcionando(client):
    pendente = cadastro_pendente(client)
    resp = client.post('/api/comercial/confirmar-email', json={'email': 'pendente@esc.com', 'codigo': pendente['codigo_dev']})
    assert resp.status_code == 200 and resp.get_json()['ok'] is True
    assert client.post('/api/escritorio/login', json={'email': 'pendente@esc.com', 'senha': SENHA}).status_code == 200


def test_falha_no_envio_em_segundo_plano_e_registrada_sem_derrubar(client, producao, monkeypatch, caplog):
    registrar_escritorio(client)

    def falha(mensagem):
        raise OSError('smtp fora do ar')

    monkeypatch.setattr(appmodule, '_enviar_mensagem_smtp', falha)
    resp = client.post('/api/escritorio/esqueci-senha', json={'email': 'existe@esc.com'})
    assert resp.status_code == 200
    for _ in range(50):
        if 'Falha em segundo plano' in caplog.text:
            break
        time.sleep(0.02)
    assert 'Falha em segundo plano' in caplog.text
    assert 'existe@esc.com' not in caplog.text
