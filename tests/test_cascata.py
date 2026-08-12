# -*- coding: utf-8 -*-
"""
Testes da exclusão segura em cascata (advogados, clientes, processos,
tentativas suspeitas e Contato Seguro) e do isolamento entre escritórios.

Rodar com:  pytest tests/test_cascata.py -v
"""
import json

from conftest import appmodule, db


def _post(client, path, token=None, body=None):
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    return client.post(path, json=body or {}, headers=headers)


def _get(client, path, token=None):
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    return client.get(path, headers=headers)


def _put(client, path, token=None, body=None):
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    return client.put(path, json=body or {}, headers=headers)


def _delete(client, path, token=None, body=None):
    headers = {'Authorization': f'Bearer {token}'} if token else {}
    return client.delete(path, json=body or {}, headers=headers)


def registrar_escritorio(client, email='escritorio@teste.com'):
    resp = _post(client, '/api/escritorio/registro', body={
        'nome': 'Escritorio Teste',
        'email': email,
        'senha': 'TesteSenha123!',
        'cnpj': ''
    })
    assert resp.status_code == 200, resp.get_json()

    with appmodule.app.app_context():
        escritorio = appmodule.Escritorio.query.filter_by(email=email).first()
        assert escritorio is not None
        escritorio.plano = 'profissional'
        escritorio.plano_expira = None
        appmodule.db.session.commit()

    return resp.get_json()['token']

def criar_advogado(client, token, nome='Dr. Fulano'):
    resp = _post(client, '/api/escritorio/advogados', token, {
        'nome': nome, 'oab': 'OAB/DF 1', 'telefone_oficial': '61999990000'
    })
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()['id']


def criar_processo(client, token, advogado_id, cliente_telefone='61988887777', cliente_nome='Cliente Teste'):
    resp = _post(client, '/api/escritorio/processos', token, {
        'advogado_id': advogado_id,
        'cliente_nome': cliente_nome,
        'cliente_telefone': cliente_telefone,
        'cliente_email': 'cliente@teste.com',
        'numero_processo': '123',
        'descricao': 'Caso teste'
    })
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()


def iniciar_cca(client, token, advogado_id, processo_id):
    resp = _post(client, '/api/escritorio/contato-seguro/iniciar', token, {
        'advogado_id': advogado_id, 'processo_id': processo_id, 'canal': 'whatsapp'
    })
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()


# ---------- Processos ----------

def test_excluir_processo_sem_vinculos(client):
    token = registrar_escritorio(client)
    adv_id = criar_advogado(client, token)
    processo = criar_processo(client, token, adv_id)

    resp = _delete(client, f'/api/escritorio/processos/{processo["id"]}', token)
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()['ok'] is True

    listagem = _get(client, '/api/escritorio/processos', token).get_json()
    assert listagem == []


def test_excluir_processo_com_contato_seguro(client):
    token = registrar_escritorio(client)
    adv_id = criar_advogado(client, token)
    processo = criar_processo(client, token, adv_id)
    iniciar_cca(client, token, adv_id, processo['id'])

    resp = _delete(client, f'/api/escritorio/processos/{processo["id"]}', token)
    assert resp.status_code == 200, resp.get_json()

    with appmodule.app.app_context():
        assert appmodule.ContatoSeguro.query.count() == 0
        assert appmodule.ContatoSeguroLog.query.count() == 0


def test_excluir_processo_com_tentativa(client):
    token = registrar_escritorio(client)
    adv_id = criar_advogado(client, token)
    processo = criar_processo(client, token, adv_id)

    with appmodule.app.app_context():
        db.session.add(appmodule.TentativaContato(
            processo_id=processo['id'], numero_suspeito='6199990000', canal='whatsapp',
            descricao='teste', confirmado_golpe=True
        ))
        db.session.commit()

    resp = _delete(client, f'/api/escritorio/processos/{processo["id"]}', token)
    assert resp.status_code == 200, resp.get_json()

    with appmodule.app.app_context():
        assert appmodule.TentativaContato.query.count() == 0
        assert appmodule.Processo.query.count() == 0


def test_resumo_exclusao_processo_mostra_contagens(client):
    token = registrar_escritorio(client)
    adv_id = criar_advogado(client, token)
    processo = criar_processo(client, token, adv_id)
    iniciar_cca(client, token, adv_id, processo['id'])

    resumo = _get(client, f'/api/escritorio/processos/{processo["id"]}/resumo-exclusao', token).get_json()
    assert resumo['contatos_seguros'] == 1


# ---------- Advogados ----------

def test_desativar_e_reativar_advogado(client):
    token = registrar_escritorio(client)
    adv_id = criar_advogado(client, token)

    resp = _post(client, f'/api/escritorio/advogados/{adv_id}/desativar', token)
    assert resp.status_code == 200
    assert resp.get_json()['ativo'] is False

    lista = _get(client, '/api/escritorio/advogados', token).get_json()
    assert lista[0]['ativo'] is False

    resp = _post(client, f'/api/escritorio/advogados/{adv_id}/reativar', token)
    assert resp.get_json()['ativo'] is True


def test_excluir_advogado_com_processos_exige_confirmacao(client):
    token = registrar_escritorio(client)
    adv_id = criar_advogado(client, token)
    criar_processo(client, token, adv_id)

    resp = _delete(client, f'/api/escritorio/advogados/{adv_id}', token)
    assert resp.status_code == 400
    assert 'EXCLUIR' in resp.get_json()['erro']


def test_excluir_definitivo_advogado_e_registros(client):
    token = registrar_escritorio(client)
    adv_id = criar_advogado(client, token)
    processo = criar_processo(client, token, adv_id)
    iniciar_cca(client, token, adv_id, processo['id'])

    with appmodule.app.app_context():
        db.session.add(appmodule.TentativaContato(
            processo_id=processo['id'], numero_suspeito='000', canal='whatsapp',
            descricao='x', confirmado_golpe=False
        ))
        db.session.commit()

    resp = _delete(client, f'/api/escritorio/advogados/{adv_id}', token, {'confirmacao': 'EXCLUIR'})
    assert resp.status_code == 200, resp.get_json()

    with appmodule.app.app_context():
        assert appmodule.Advogado.query.count() == 0
        assert appmodule.Processo.query.count() == 0
        assert appmodule.TentativaContato.query.count() == 0
        assert appmodule.ContatoSeguro.query.count() == 0


# ---------- Clientes ----------

def test_listar_editar_desativar_cliente(client):
    token = registrar_escritorio(client)
    adv_id = criar_advogado(client, token)
    processo = criar_processo(client, token, adv_id)

    lista = _get(client, '/api/escritorio/clientes', token).get_json()
    assert len(lista) == 1
    cliente_id = lista[0]['id']

    resp = _put(client, f'/api/escritorio/clientes/{cliente_id}', token, {'nome': 'Novo Nome'})
    assert resp.get_json()['nome'] == 'Novo Nome'

    resp = _post(client, f'/api/escritorio/clientes/{cliente_id}/desativar', token)
    assert resp.get_json()['ativo'] is False


def test_excluir_definitivo_cliente(client):
    token = registrar_escritorio(client)
    adv_id = criar_advogado(client, token)
    processo = criar_processo(client, token, adv_id)
    cliente_id = processo['cliente_id']

    resp = _delete(client, f'/api/escritorio/clientes/{cliente_id}', token, {'confirmacao': 'EXCLUIR'})
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()['cliente_removido'] is True

    with appmodule.app.app_context():
        assert appmodule.Cliente.query.count() == 0
        assert appmodule.Processo.query.count() == 0


# ---------- Isolamento entre escritórios ----------

def test_impede_escritorio_excluir_processo_de_outro(client):
    token_a = registrar_escritorio(client, 'a@teste.com')
    token_b = registrar_escritorio(client, 'b@teste.com')

    adv_a = criar_advogado(client, token_a)
    processo_a = criar_processo(client, token_a, adv_a)

    resp = _delete(client, f'/api/escritorio/processos/{processo_a["id"]}', token_b)
    assert resp.status_code == 404

    with appmodule.app.app_context():
        assert appmodule.Processo.query.count() == 1


def test_impede_escritorio_excluir_advogado_de_outro(client):
    token_a = registrar_escritorio(client, 'a@teste.com')
    token_b = registrar_escritorio(client, 'b@teste.com')
    adv_a = criar_advogado(client, token_a)

    resp = _delete(client, f'/api/escritorio/advogados/{adv_a}', token_b, {'confirmacao': 'EXCLUIR'})
    assert resp.status_code == 404

    with appmodule.app.app_context():
        assert appmodule.Advogado.query.count() == 1


def test_cliente_compartilhado_entre_escritorios_preserva_registro_do_outro(client):
    token_a = registrar_escritorio(client, 'a@teste.com')
    token_b = registrar_escritorio(client, 'b@teste.com')

    adv_a = criar_advogado(client, token_a)
    adv_b = criar_advogado(client, token_b)

    telefone_comum = '61977776666'
    criar_processo(client, token_a, adv_a, cliente_telefone=telefone_comum)
    criar_processo(client, token_b, adv_b, cliente_telefone=telefone_comum)

    lista_a = _get(client, '/api/escritorio/clientes', token_a).get_json()
    cliente_id = lista_a[0]['id']

    resp = _delete(client, f'/api/escritorio/clientes/{cliente_id}', token_a, {'confirmacao': 'EXCLUIR'})
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()['cliente_removido'] is False

    with appmodule.app.app_context():
        # cliente preservado (ainda usado pelo escritório B)
        assert appmodule.Cliente.query.count() == 1
        # o processo do escritório A foi removido, o do B permanece
        assert appmodule.Processo.query.count() == 1
        assert appmodule.Processo.query.first().escritorio_id == appmodule.Escritorio.query.filter_by(email='b@teste.com').first().id


# ---------- Tentativas e Contato Seguro: exclusão individual/lote ----------

def test_excluir_tentativa_individual_e_lote(client):
    token = registrar_escritorio(client)
    adv_id = criar_advogado(client, token)
    processo = criar_processo(client, token, adv_id)

    with appmodule.app.app_context():
        for i in range(3):
            db.session.add(appmodule.TentativaContato(
                processo_id=processo['id'], numero_suspeito=str(i), canal='whatsapp',
                descricao='t', confirmado_golpe=False
            ))
        db.session.commit()
        ids = [t.id for t in appmodule.TentativaContato.query.all()]

    resp = _delete(client, f'/api/escritorio/tentativas/{ids[0]}', token)
    assert resp.status_code == 200

    resp = _post(client, '/api/escritorio/tentativas/excluir-lote', token, {'ids': ids[1:]})
    assert resp.status_code == 200
    assert resp.get_json()['excluidos'] == 2

    with appmodule.app.app_context():
        assert appmodule.TentativaContato.query.count() == 0


def test_excluir_contato_seguro_individual_e_lote(client):
    token = registrar_escritorio(client)
    adv_id = criar_advogado(client, token)
    processo = criar_processo(client, token, adv_id)

    cca1 = iniciar_cca(client, token, adv_id, processo['id'])
    cca2 = iniciar_cca(client, token, adv_id, processo['id'])

    resp = _delete(client, f'/api/escritorio/contato-seguro/{cca1["id"]}', token)
    assert resp.status_code == 200

    resp = _post(client, '/api/escritorio/contato-seguro/excluir-lote', token, {'ids': [cca2['id']]})
    assert resp.status_code == 200
    assert resp.get_json()['excluidos'] == 1

    with appmodule.app.app_context():
        assert appmodule.ContatoSeguro.query.count() == 0
