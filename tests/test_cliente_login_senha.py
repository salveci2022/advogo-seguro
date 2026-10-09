# -*- coding: utf-8 -*-
"""O login do cliente deve aceitar senha alfanumérica completa (letras, números e símbolos)."""
import re


def _input(html, campo_id):
    tag = re.search(r'<input[^>]*id="%s"[^>]*>' % campo_id, html)
    assert tag, campo_id
    return tag.group(0)


def test_campo_senha_cliente_nao_forca_teclado_numerico(client):
    html = client.get('/cliente/login').get_data(as_text=True)
    senha = _input(html, 'senha')
    assert 'type="password"' in senha
    assert 'inputmode' not in senha
    assert 'pattern' not in senha
    assert 'type="number"' not in senha


def test_campo_telefone_cliente_continua_numerico(client):
    html = client.get('/cliente/login').get_data(as_text=True)
    telefone = _input(html, 'telefone')
    assert 'type="tel"' in telefone
    assert 'inputmode="tel"' in telefone
