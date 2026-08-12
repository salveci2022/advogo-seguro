# -*- coding: utf-8 -*-
"""Testes da Camada 7 — Infraestrutura."""
from pathlib import Path
from sqlalchemy.exc import OperationalError

import app as appmodule

ROOT = Path(__file__).resolve().parents[1]


def test_health_check_confirma_banco(client):
    resp = client.get('/api/health')
    assert resp.status_code == 200
    dados = resp.get_json()
    assert dados['status'] == 'ok'
    assert dados['database'] == 'ok'
    assert 'timestamp' in dados


def test_health_check_retorna_503_quando_banco_falha(client, monkeypatch):
    def falhar(*args, **kwargs):
        raise OperationalError('SELECT 1', {}, Exception('db off'))

    monkeypatch.setattr(appmodule.db.session, 'execute', falhar)
    resp = client.get('/api/health')
    assert resp.status_code == 503
    dados = resp.get_json()
    assert dados['status'] == 'degraded'
    assert dados['database'] == 'unavailable'


def test_producao_recusa_database_url_ausente_ou_sqlite():
    for url in ('', 'sqlite:///advogo_seguro.db'):
        try:
            appmodule._validar_database_url_infra(url, True)
        except RuntimeError:
            pass
        else:
            raise AssertionError(f'Produção aceitou DATABASE_URL insegura: {url!r}')


def test_producao_aceita_postgresql_e_dev_aceita_sqlite():
    assert appmodule._validar_database_url_infra(
        'postgresql://usuario:senha@host:5432/db', True
    ).startswith('postgresql://')
    assert appmodule._validar_database_url_infra('', False) == 'sqlite:///advogo_seguro.db'


def test_render_yaml_tem_healthcheck_porta_e_gunicorn_controlado():
    texto = (ROOT / 'render.yaml').read_text(encoding='utf-8')
    assert 'healthCheckPath: /api/health' in texto
    assert '--bind 0.0.0.0:$PORT' in texto
    assert '--workers 1' in texto
    assert '--threads 4' in texto
    assert '--graceful-timeout 30' in texto
    assert 'PYTHONUNBUFFERED' in texto


def test_procfile_alinhado_com_render():
    proc = (ROOT / 'Procfile').read_text(encoding='utf-8')
    render = (ROOT / 'render.yaml').read_text(encoding='utf-8')
    assert '--bind 0.0.0.0:$PORT' in proc
    assert '--workers 1' in proc
    assert '--threads 4' in proc
    assert '--bind 0.0.0.0:$PORT' in render


def test_gitignore_protege_segredos_banco_e_uploads():
    texto = (ROOT / '.gitignore').read_text(encoding='utf-8')
    for item in ('.env', 'instance/', '*.db', '.venv/', 'static/uploads/'):
        assert item in texto
