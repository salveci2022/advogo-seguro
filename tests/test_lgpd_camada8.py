# -*- coding: utf-8 -*-
from datetime import timedelta
import app as appmodule

db = appmodule.db
Cliente = appmodule.Cliente
AcessoPublicoLog = appmodule.AcessoPublicoLog
SolicitacaoPrivacidade = appmodule.SolicitacaoPrivacidade


def criar_cliente(telefone, email):
    cliente = Cliente(
        nome='Cliente Privacidade',
        telefone=telefone,
        email=email,
        senha_hash=appmodule.hash_senha('SenhaCliente123!'),
    )
    db.session.add(cliente)
    db.session.commit()
    return cliente.id


def login_cliente(client, telefone):
    resp = client.post('/api/cliente/login', json={
        'telefone': telefone, 'senha': 'SenhaCliente123!'
    })
    assert resp.status_code == 200, resp.get_json()
    return {'Authorization': f"Bearer {resp.get_json()['token']}"}


def registrar_escritorio(client, email='privacidade-escritorio@teste.com'):
    resp = client.post('/api/escritorio/registro', json={
        'nome': 'Escritório Privacidade',
        'email': email,
        'senha': 'SenhaEscritorio123!',
    })
    assert resp.status_code == 200, resp.get_json()
    return {'Authorization': f"Bearer {resp.get_json()['token']}"}


def test_aviso_privacidade_publico(client):
    resp = client.get('/privacidade')
    assert resp.status_code == 200
    texto = resp.get_data(as_text=True)
    assert 'Aviso de Privacidade' in texto
    assert 'Direitos do titular' in texto
    assert 'Configuração pendente' in texto or appmodule.PRIVACY_CONTACT_EMAIL in texto


def test_ip_pseudonimizado_nao_guarda_ip_bruto():
    ip = '203.0.113.42'
    valor = appmodule._pseudonimizar_ip(ip)
    assert valor.startswith('h:')
    assert ip not in valor
    assert valor == appmodule._pseudonimizar_ip(ip)


def test_migracao_ip_legado_substitui_valor_bruto(client):
    with appmodule.app.app_context():
        log = AcessoPublicoLog(processo_id=None, acao='visualizou', ip='198.51.100.20')
        db.session.add(log)
        db.session.commit()
        log_id = log.id
        assert appmodule._migrar_ips_legados_para_hash() >= 1
        atualizado = db.session.get(AcessoPublicoLog, log_id)
        assert atualizado.ip.startswith('h:')
        assert '198.51.100.20' not in atualizado.ip


def test_exportacao_cliente_nao_expoe_segredos(client):
    with appmodule.app.app_context():
        criar_cliente('61990000001', 'titular1@teste.com')
    headers = login_cliente(client, '61990000001')
    resp = client.get('/api/cliente/privacidade/exportar', headers=headers)
    assert resp.status_code == 200
    assert resp.get_json()['titular']['telefone'] == '61990000001'
    bruto = resp.get_data(as_text=True)
    for segredo in ('senha_hash', 'reset_token', 'token_cliente', 'advogo_seguro_auth'):
        assert segredo not in bruto


def test_exportacao_escritorio_nao_expoe_senha_nem_blob(client):
    headers = registrar_escritorio(client)
    r = client.post('/api/escritorio/advogados', json={
        'nome': 'Dra. Privacidade', 'telefone_oficial': '61990000002'
    }, headers=headers)
    assert r.status_code == 200
    resp = client.get('/api/escritorio/privacidade/exportar', headers=headers)
    assert resp.status_code == 200
    bruto = resp.get_data(as_text=True)
    assert 'Dra. Privacidade' in bruto
    for segredo in ('senha_hash', 'reset_token', 'foto_blob', 'foto_token'):
        assert segredo not in bruto


def test_cliente_cria_e_lista_solicitacao_sem_copiar_pii(client):
    with appmodule.app.app_context():
        cid = criar_cliente('61990000003', 'titular3@teste.com')
    headers = login_cliente(client, '61990000003')
    resp = client.post('/api/cliente/privacidade/solicitacoes', json={
        'tipo': 'correcao', 'detalhes': 'Desejo corrigir um dado cadastral.'
    }, headers=headers)
    assert resp.status_code == 201
    lista = client.get('/api/cliente/privacidade/solicitacoes', headers=headers)
    assert lista.status_code == 200
    assert len(lista.get_json()) == 1
    with appmodule.app.app_context():
        item = SolicitacaoPrivacidade.query.first()
        assert item.referencia_titular == appmodule._referencia_privacidade('cliente', cid)
        assert '61990000003' not in item.referencia_titular


def test_solicitacao_tipo_invalido_rejeitada(client):
    with appmodule.app.app_context():
        criar_cliente('61990000004', 'titular4@teste.com')
    headers = login_cliente(client, '61990000004')
    resp = client.post('/api/cliente/privacidade/solicitacoes', json={
        'tipo': 'apagar_tudo_sem_analise'
    }, headers=headers)
    assert resp.status_code == 400


def test_solicitacoes_ficam_isoladas_por_titular(client):
    with appmodule.app.app_context():
        criar_cliente('61990000005', 'titular5@teste.com')
        criar_cliente('61990000006', 'titular6@teste.com')
    h1 = login_cliente(client, '61990000005')
    r = client.post('/api/cliente/privacidade/solicitacoes', json={'tipo': 'acesso'}, headers=h1)
    assert r.status_code == 201
    h2 = login_cliente(client, '61990000006')
    lista2 = client.get('/api/cliente/privacidade/solicitacoes', headers=h2)
    assert lista2.status_code == 200
    assert lista2.get_json() == []


def test_retencao_so_remove_log_antigo_quando_chamada(client):
    with appmodule.app.app_context():
        antigo = AcessoPublicoLog(
            processo_id=None, acao='visualizou',
            ip=appmodule._pseudonimizar_ip('192.0.2.1'),
            criado_em=appmodule.agora_utc() - timedelta(days=40),
        )
        recente = AcessoPublicoLog(
            processo_id=None, acao='visualizou',
            ip=appmodule._pseudonimizar_ip('192.0.2.2'),
            criado_em=appmodule.agora_utc() - timedelta(days=2),
        )
        db.session.add_all([antigo, recente])
        db.session.commit()
        antigo_id, recente_id = antigo.id, recente.id
        resultado = appmodule._aplicar_retencao_logs_privacidade(30)
        assert resultado['acessos_publicos_logs'] == 1
        assert db.session.get(AcessoPublicoLog, antigo_id) is None
        assert db.session.get(AcessoPublicoLog, recente_id) is not None
