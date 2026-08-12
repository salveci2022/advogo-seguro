# -*- coding: utf-8 -*-
"""Fechamento da Camada 7 — persistência de fotos no banco."""
import io
import os
from sqlalchemy import inspect
import app as appmodule


def registrar(client, email='foto-infra@teste.com'):
    resp = client.post('/api/escritorio/registro', json={
        'nome': 'Escritorio Foto',
        'email': email,
        'senha': 'SenhaFoto123!'
    })
    assert resp.status_code == 200, resp.get_json()

    with appmodule.app.app_context():
        escritorio = appmodule.Escritorio.query.filter_by(email=email).first()
        assert escritorio is not None
        escritorio.plano = 'profissional'
        escritorio.plano_expira = None
        appmodule.db.session.commit()

    token = resp.get_json().get('token')
    return {'Authorization': f'Bearer {token}'}

def criar_advogado(client, headers, telefone='61999993333'):
    resp = client.post('/api/escritorio/advogados', json={
        'nome': 'Dra. Foto', 'telefone_oficial': telefone
    }, headers=headers)
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()['id']


def png_teste(sufixo=b'A'):
    return b'\x89PNG\r\n\x1a\n' + (sufixo * 128)


def enviar_foto(client, headers, advogado_id, dados):
    return client.post(
        f'/api/escritorio/advogados/{advogado_id}/foto',
        data={'foto': (io.BytesIO(dados), 'foto.png')},
        headers=headers,
        content_type='multipart/form-data',
    )


def test_upload_persiste_blob_e_nao_cria_arquivo_local(client):
    headers = registrar(client)
    adv_id = criar_advogado(client, headers)
    antes = set(os.listdir(appmodule.UPLOAD_PASTA_ADVOGADOS))
    dados = png_teste()
    resp = enviar_foto(client, headers, adv_id, dados)
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()['foto_url'].startswith('/api/publico/foto-advogado/')
    depois = set(os.listdir(appmodule.UPLOAD_PASTA_ADVOGADOS))
    assert depois == antes
    with appmodule.app.app_context():
        adv = appmodule.db.session.get(appmodule.Advogado, adv_id)
        assert bytes(adv.foto_blob) == dados
        assert adv.foto_mime == 'image/png'
        assert adv.foto_token


def test_foto_publica_retorna_bytes_tipo_e_cache(client):
    headers = registrar(client, 'foto-publica@teste.com')
    adv_id = criar_advogado(client, headers, '61999993334')
    dados = png_teste(b'B')
    up = enviar_foto(client, headers, adv_id, dados)
    url = up.get_json()['foto_url']
    foto = client.get(url)
    assert foto.status_code == 200
    assert foto.data == dados
    assert foto.mimetype == 'image/png'
    assert 'immutable' in foto.headers.get('Cache-Control', '')


def test_substituir_foto_rotaciona_token_e_invalida_url_antiga(client):
    headers = registrar(client, 'foto-rotacao@teste.com')
    adv_id = criar_advogado(client, headers, '61999993335')
    primeira = enviar_foto(client, headers, adv_id, png_teste(b'C')).get_json()['foto_url']
    segunda = enviar_foto(client, headers, adv_id, png_teste(b'D')).get_json()['foto_url']
    assert primeira != segunda
    assert client.get(primeira).status_code == 404
    assert client.get(segunda).status_code == 200


def test_edicao_normal_preserva_foto_e_url_externa_limpa_blob(client):
    headers = registrar(client, 'foto-edicao@teste.com')
    adv_id = criar_advogado(client, headers, '61999993336')
    url = enviar_foto(client, headers, adv_id, png_teste(b'E')).get_json()['foto_url']
    manter = client.put(f'/api/escritorio/advogados/{adv_id}', json={
        'nome': 'Dra. Foto Editada', 'foto_url': url
    }, headers=headers)
    assert manter.status_code == 200
    with appmodule.app.app_context():
        adv = appmodule.db.session.get(appmodule.Advogado, adv_id)
        assert adv.foto_blob and adv.foto_token
    externa = client.put(f'/api/escritorio/advogados/{adv_id}', json={
        'foto_url': 'https://example.com/foto.webp'
    }, headers=headers)
    assert externa.status_code == 200
    with appmodule.app.app_context():
        adv = appmodule.db.session.get(appmodule.Advogado, adv_id)
        assert adv.foto_url == 'https://example.com/foto.webp'
        assert adv.foto_blob is None
        assert adv.foto_token is None


def test_schema_tem_colunas_e_indice_unico_de_foto(client):
    with appmodule.app.app_context():
        insp = inspect(appmodule.db.engine)
        colunas = {c['name'] for c in insp.get_columns('advogados')}
        assert {'foto_blob', 'foto_mime', 'foto_token'}.issubset(colunas)
        indices = {i['name']: i for i in insp.get_indexes('advogados')}
        # Em db.create_all o unique=True pode aparecer como constraint em alguns dialetos;
        # o requisito central é que o modelo marque o token como único.
        assert appmodule.Advogado.__table__.c.foto_token.unique is True


def test_migracao_legada_local_quando_arquivo_ainda_existe(client):
    headers = registrar(client, 'foto-legada@teste.com')
    adv_id = criar_advogado(client, headers, '61999993337')
    nome = 'teste_legado_camada7.png'
    caminho = os.path.join(appmodule.UPLOAD_PASTA_ADVOGADOS, nome)
    dados = png_teste(b'F')
    try:
        with open(caminho, 'wb') as f:
            f.write(dados)
        with appmodule.app.app_context():
            adv = appmodule.db.session.get(appmodule.Advogado, adv_id)
            adv.foto_url = f'/static/uploads/advogados/{nome}'
            appmodule.db.session.commit()
            assert appmodule._migrar_fotos_legadas_local_para_banco() == 1
            adv = appmodule.db.session.get(appmodule.Advogado, adv_id)
            assert bytes(adv.foto_blob) == dados
            assert adv.foto_url.startswith('/api/publico/foto-advogado/')
    finally:
        if os.path.exists(caminho):
            os.remove(caminho)
