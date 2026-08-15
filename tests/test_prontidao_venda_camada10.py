# -*- coding: utf-8 -*-
from pathlib import Path
import app as appmodule

ROOT = Path(__file__).resolve().parents[1]


def test_release_tem_versao_1_1_0_e_health_expoe_versao(client):
    assert appmodule.APP_VERSION == '1.1.0'
    resp = client.get('/api/health')
    assert resp.status_code == 200
    dados = resp.get_json()
    assert dados['version'] == '1.1.0'
    assert dados['status'] == 'ok'
    assert dados['database'] == 'ok'


def test_execucao_direta_nao_tem_debug_true_hardcoded():
    texto = (ROOT / 'app.py').read_text(encoding='utf-8')
    assert 'app.run(debug=True' not in texto
    assert 'debug=debug_local' in texto
    assert 'and not IS_PRODUCTION' in texto


def test_stack_producao_tem_gunicorn_postgresql_e_python_fixado():
    req = (ROOT / 'requirements.txt').read_text(encoding='utf-8')
    runtime = (ROOT / 'runtime.txt').read_text(encoding='utf-8').strip()
    proc = (ROOT / 'Procfile').read_text(encoding='utf-8')
    assert 'gunicorn==' in req
    assert 'psycopg2-binary==' in req
    assert runtime == '3.11.9'
    assert 'gunicorn app:app' in proc
    assert '--bind 0.0.0.0:$PORT' in proc


def test_render_declara_versao_healthcheck_e_variaveis_criticas():
    texto = (ROOT / 'render.yaml').read_text(encoding='utf-8')
    for item in (
        'APP_VERSION', 'value: 1.1.0', 'healthCheckPath: /api/health',
        'DATABASE_URL', 'SECRET_KEY', 'JWT_SECRET',
        'PRIVACY_CONTACT_EMAIL', 'COMMERCIAL_WHATSAPP', 'COMMERCIAL_EMAIL',
        'STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'STRIPE_PRICE_MAP',
        'TRIAL_DIAS', 'value: 2', 'COMMERCIAL_FLOW_ENABLED',
    ):
        assert item in texto


def test_paginas_publicas_essenciais_abrem(client):
    for rota in (
        '/', '/planos', '/privacidade', '/escritorio/login',
        '/escritorio/cadastro', '/cliente/login', '/verificar',
        '/confirmar-email', '/contratacao', '/contratacao/sucesso',
    ):
        resp = client.get(rota)
        assert resp.status_code == 200, (rota, resp.status_code)


def test_release_comercial_nao_tem_placeholder_de_contato(client):
    planos = client.get('/planos').get_data(as_text=True)
    home = client.get('/').get_data(as_text=True)
    assert 'Substitua este texto' not in planos
    assert 'Substitua este texto' not in home
    assert '1.597' in planos
    assert 'Aviso de Privacidade' in planos


def test_preflight_nao_imprime_valores_de_segredos():
    texto = (ROOT / 'scripts' / 'preflight_venda.py').read_text(encoding='utf-8')
    assert 'os.environ.get("SECRET_KEY"' not in texto
    assert 'os.environ.get("JWT_SECRET"' not in texto
    assert 'os.environ.get("ADMIN_SECRET"' not in texto
    assert 'APROVADO PARA DEPLOY COMERCIAL' in texto
    assert 'REPROVADO PARA DEPLOY COMERCIAL' in texto


def test_release_tem_documentacao_de_deploy_backup_e_rollback():
    release = (ROOT / 'docs' / 'RELEASE_1.0.0.md').read_text(encoding='utf-8')
    deploy = (ROOT / 'docs' / 'CHECKLIST_DEPLOY_COMERCIAL.md').read_text(encoding='utf-8')
    rollback = (ROOT / 'docs' / 'PLANO_ROLLBACK.md').read_text(encoding='utf-8')
    assert 'backup' in release.lower()
    assert 'preflight_venda.py' in deploy
    assert 'smoke_pos_deploy.py' in deploy
    assert 'rollback' in rollback.lower()
    assert '/api/health' in rollback


def test_gitignore_exclui_segredos_bancos_uploads_e_backups():
    texto = (ROOT / '.gitignore').read_text(encoding='utf-8')
    for item in (
        '.env', '*.db', 'static/uploads/', 'backups/',
        'app.py.backup*', 'templates/*.backup*',
    ):
        assert item in texto


def test_smoke_pos_deploy_cobre_rotas_criticas_sem_credenciais():
    texto = (ROOT / 'scripts' / 'smoke_pos_deploy.py').read_text(encoding='utf-8')
    for rota in ('/api/health', '/planos', '/privacidade', '/escritorio/login', '/cliente/login'):
        assert rota in texto
    assert 'Authorization' not in texto
    assert 'senha' not in texto.lower()
