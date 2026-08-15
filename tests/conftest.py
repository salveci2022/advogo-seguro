# -*- coding: utf-8 -*-
"""
Configuração compartilhada dos testes automatizados do ADVOGO SEGURO.

Usa SQLite em memória (isolado por teste) para não tocar em nenhum banco
real. Define as variáveis de ambiente ANTES de importar app.py, pois o
módulo cria a app e conecta ao banco na hora do import.
"""
import os
import sys

os.environ.setdefault('SECRET_KEY', 'teste-secret')
os.environ.setdefault('JWT_SECRET', 'teste-jwt-secret')
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

import app as appmodule  # noqa: E402

flask_app = appmodule.app
db = appmodule.db


@pytest.fixture()
def client():
    flask_app.config['TESTING'] = True
    appmodule._tentativas_login.clear()
    appmodule._tentativas_acoes.clear()
    with flask_app.app_context():
        db.drop_all()
        db.create_all()
    with flask_app.test_client() as test_client:
        yield test_client
    with flask_app.app_context():
        db.session.remove()
        db.drop_all()
