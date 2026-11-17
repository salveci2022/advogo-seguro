# -*- coding: utf-8 -*-
"""Correção 2 pós-Etapa 6: tokens de URL nunca vão inteiros para os logs.

Cobre o mascaramento, o filtro de logging da aplicação, o logger do Gunicorn (atoms do log de
acesso), mensagens de exceção do banco (hide_parameters) e a configuração de execução.
"""
import io
import logging
import os
import re
from datetime import timedelta

import pytest
from sqlalchemy.exc import IntegrityError

import seguranca_logs
from conftest import appmodule

db = appmodule.db
RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN = 'Abc_DEF-123ghiJKL456mnoPQR789stuVWX0yz'


# ---------- mascaramento ----------

@pytest.mark.parametrize('entrada,esperado', [
    (f'GET /cliente/seguro/{TOKEN} HTTP/1.1', 'GET /cliente/seguro/*** HTTP/1.1'),
    (f'/cliente/verificar/{TOKEN}', '/cliente/verificar/***'),
    (f'/cliente/alerta/{TOKEN}?x=1', '/cliente/alerta/***?x=1'),
    (f'/api/cliente-publico/seguro/{TOKEN}', '/api/cliente-publico/seguro/***'),
    (f'/api/cliente-publico/contato-seguro/{TOKEN}', '/api/cliente-publico/contato-seguro/***'),
    (f'/api/cliente-publico/contato-ativo/{TOKEN}', '/api/cliente-publico/contato-ativo/***'),
    (f'POST /api/cliente-publico/registrar-alerta/{TOKEN} HTTP/1.1', 'POST /api/cliente-publico/registrar-alerta/*** HTTP/1.1'),
    (f'/api/cliente-publico/analisar-golpe/{TOKEN}', '/api/cliente-publico/analisar-golpe/***'),
    (f'/api/publico/foto-advogado/{TOKEN}', '/api/publico/foto-advogado/***'),
    (f'/redefinir-senha?tipo=cliente&token={TOKEN}', '/redefinir-senha?tipo=cliente&token=***'),
    (f'/redefinir-senha?token={TOKEN}&tipo=escritorio', '/redefinir-senha?token=***&tipo=escritorio'),
    (f'"https://advogo.example/cliente/seguro/{TOKEN}"', '"https://advogo.example/cliente/seguro/***"'),
])
def test_mascara_tokens_conhecidos(entrada, esperado):
    assert seguranca_logs.mascarar_tokens(entrada) == esperado
    assert TOKEN not in seguranca_logs.mascarar_tokens(entrada)


@pytest.mark.parametrize('texto', [
    'GET /cliente/login HTTP/1.1', 'GET /cliente/area HTTP/1.1', 'POST /api/cliente/login HTTP/1.1',
    'GET /api/escritorio/processos HTTP/1.1', 'GET /api/health HTTP/1.1', '200', '',
])
def test_nao_altera_o_que_nao_e_token(texto):
    assert seguranca_logs.mascarar_tokens(texto) == texto


@pytest.mark.parametrize('valor', [None, 200, 1.5, b'/cliente/seguro/x', ['a']])
def test_ignora_tipos_nao_textuais(valor):
    assert seguranca_logs.mascarar_tokens(valor) == valor


def test_mascaramento_e_idempotente():
    uma = seguranca_logs.mascarar_tokens(f'/cliente/seguro/{TOKEN}')
    assert seguranca_logs.mascarar_tokens(uma) == uma


# ---------- filtro de logging ----------

def _logger_capturado(nome):
    logger = logging.getLogger(nome)
    logger.handlers, logger.propagate = [], False
    saida = io.StringIO()
    handler = logging.StreamHandler(saida)
    handler.setFormatter(logging.Formatter('%(levelname)s %(message)s'))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    seguranca_logs.instalar_filtro(logger)
    return logger, saida


def test_filtro_mascara_mensagem_com_argumentos():
    logger, saida = _logger_capturado('teste.filtro.args')
    logger.info('acesso %s status=%s', f'/cliente/seguro/{TOKEN}', 200)
    texto = saida.getvalue()
    assert TOKEN not in texto and '/cliente/seguro/*** status=200' in texto


def test_filtro_mascara_traceback():
    logger, saida = _logger_capturado('teste.filtro.exc')
    try:
        raise RuntimeError(f'falhou em /redefinir-senha?token={TOKEN}')
    except RuntimeError:
        logger.exception('erro ao processar')
    texto = saida.getvalue()
    assert 'RuntimeError' in texto and 'token=***' in texto and TOKEN not in texto


def test_filtro_preserva_mensagens_sem_token():
    logger, saida = _logger_capturado('teste.filtro.limpo')
    logger.info('[SESSAO] revogacao cliente_id=%s origem=%s', 7, 'cliente')
    assert saida.getvalue().strip() == 'INFO [SESSAO] revogacao cliente_id=7 origem=cliente'


def test_instalar_filtro_e_idempotente():
    logger = logging.getLogger('teste.filtro.idempotente')
    seguranca_logs.instalar_filtro(logger)
    seguranca_logs.instalar_filtro(logger)
    assert sum(isinstance(f, seguranca_logs.FiltroTokens) for f in logger.filters) == 1


def test_aplicacao_e_werkzeug_tem_o_filtro():
    for logger in (appmodule.app.logger, logging.getLogger('werkzeug')):
        assert any(isinstance(f, seguranca_logs.FiltroTokens) for f in logger.filters), logger.name


def test_erro_inesperado_em_rota_publica_nao_registra_token(client, monkeypatch, caplog):
    def explode(token, escrita=False):
        raise RuntimeError(f'falha inesperada em /api/cliente-publico/seguro/{token}')

    monkeypatch.setattr(appmodule, '_limite_link_seguro', explode)
    with caplog.at_level(logging.INFO):
        resp = client.get(f'/api/cliente-publico/seguro/{TOKEN}')
    assert resp.status_code == 500
    assert TOKEN not in resp.get_data(as_text=True)
    assert 'Erro inesperado' in caplog.text and TOKEN not in caplog.text


def test_mensagens_de_erro_do_banco_nao_trazem_valores(client):
    """hide_parameters: IntegrityError não carrega o token (nem outros valores) na mensagem."""
    assert appmodule.app.config['SQLALCHEMY_ENGINE_OPTIONS']['hide_parameters'] is True
    with appmodule.app.app_context():
        esc = appmodule.Escritorio(nome='E', email='e@hide.com', senha_hash='x')
        cli = appmodule.Cliente(nome='C', telefone='61900009999', senha_hash='x')
        db.session.add_all([esc, cli])
        db.session.flush()
        adv = appmodule.Advogado(escritorio_id=esc.id, nome='A', telefone_oficial='61900008888')
        db.session.add(adv)
        db.session.flush()
        for codigo in ('COD00001', 'COD00002'):
            db.session.add(appmodule.Processo(escritorio_id=esc.id, advogado_id=adv.id, cliente_id=cli.id,
                                              codigo_unico=codigo, token_cliente=TOKEN))
        with pytest.raises(IntegrityError) as erro:
            db.session.commit()
        db.session.rollback()
    assert TOKEN not in str(erro.value)


# ---------- logger do Gunicorn ----------

class _LoggerBaseFalso:
    """Imita gunicorn.glogging.Logger.atoms/setup para testar o mixin sem o Gunicorn (Windows)."""

    def __init__(self):
        self.error_log = logging.getLogger('teste.gunicorn.error')
        self.access_log = logging.getLogger('teste.gunicorn.access')

    def setup(self, cfg):
        pass

    def atoms(self, resp, req, environ, request_time):
        return {
            'h': '203.0.113.9', 't': '[16/Nov/2026:20:00:00 -0300]', 's': '200',
            'r': f"{environ['REQUEST_METHOD']} {environ['RAW_URI']} HTTP/1.1",
            'U': environ['PATH_INFO'], 'q': environ['QUERY_STRING'], 'M': 12, 'B': 345,
            'f': environ.get('HTTP_REFERER', '-'),
            '{raw_uri}e': environ['RAW_URI'], '{path_info}e': environ['PATH_INFO'],
            '{query_string}e': environ['QUERY_STRING'],
        }


class _LoggerComMixin(seguranca_logs.MascaraTokensGunicornMixin, _LoggerBaseFalso):
    pass


@pytest.mark.parametrize('caminho,query', [
    (f'/cliente/seguro/{TOKEN}', ''),
    (f'/api/cliente-publico/registrar-alerta/{TOKEN}', ''),
    ('/redefinir-senha', f'tipo=cliente&token={TOKEN}'),
])
def test_mixin_mascara_atoms_e_preserva_dados_operacionais(caminho, query):
    raw = caminho + (f'?{query}' if query else '')
    environ = {'REQUEST_METHOD': 'GET', 'RAW_URI': raw, 'PATH_INFO': caminho, 'QUERY_STRING': query,
               'HTTP_REFERER': f'https://advogo.example{raw}'}
    atoms = _LoggerComMixin().atoms(None, None, environ, timedelta(milliseconds=12))
    assert all(TOKEN not in str(v) for v in atoms.values())
    assert atoms['s'] == '200' and atoms['M'] == 12 and atoms['B'] == 345
    assert atoms['h'] == '203.0.113.9' and atoms['t'].startswith('[16/Nov/2026')
    assert atoms['r'].startswith('GET /') and '***' in atoms['r']


def test_mixin_instala_filtro_nos_logs_do_servidor():
    logger = _LoggerComMixin()
    logger.setup(cfg=None)
    for alvo in (logger.error_log, logger.access_log):
        assert any(isinstance(f, seguranca_logs.FiltroTokens) for f in alvo.filters)


@pytest.mark.skipif(getattr(seguranca_logs, 'LoggerSemTokens', None) is None,
                    reason='Gunicorn não roda neste sistema (Windows); coberto no CI Linux')
def test_logger_real_do_gunicorn_grava_acesso_sem_token():
    from gunicorn.config import Config

    cfg = Config()
    cfg.set('accesslog', '-')
    logger = seguranca_logs.LoggerSemTokens(cfg)
    saida = io.StringIO()
    logger.access_log.handlers = [logging.StreamHandler(saida)]

    class Resposta:
        status, sent, headers = '200 OK', 345, [('Content-Type', 'application/json')]

    class Requisicao:
        headers = [('User-Agent', 'teste')]

    environ = {'REQUEST_METHOD': 'GET', 'RAW_URI': f'/cliente/seguro/{TOKEN}', 'PATH_INFO': f'/cliente/seguro/{TOKEN}',
               'QUERY_STRING': '', 'SERVER_PROTOCOL': 'HTTP/1.1', 'REMOTE_ADDR': '203.0.113.9'}
    logger.access(Resposta(), Requisicao(), environ, timedelta(milliseconds=12))
    linha = saida.getvalue()
    assert TOKEN not in linha
    assert '"GET /cliente/seguro/*** HTTP/1.1" 200 345' in linha


# ---------- configuração de execução ----------

def test_gunicorn_conf_define_o_logger():
    conf = {}
    with open(os.path.join(RAIZ, 'gunicorn.conf.py'), encoding='utf-8') as arquivo:
        exec(compile(arquivo.read(), 'gunicorn.conf.py', 'exec'), conf)
    assert conf['logger_class'] == 'seguranca_logs.LoggerSemTokens'
    modulo, classe = conf['logger_class'].rsplit('.', 1)
    assert modulo == seguranca_logs.__name__ and hasattr(seguranca_logs, 'MascaraTokensGunicornMixin')


@pytest.mark.parametrize('arquivo', ['Procfile', 'render.yaml'])
def test_comando_de_inicio_nao_ignora_o_gunicorn_conf(arquivo):
    """O comando de início não pode trocar o logger nem apontar outro arquivo de configuração.

    Indicar explicitamente o próprio gunicorn.conf.py (-c/--config gunicorn.conf.py) é permitido e
    recomendado (docs/CHECKLIST_DEPLOY_1.2.0.md, item 3).
    """
    with open(os.path.join(RAIZ, arquivo), encoding='utf-8') as f:
        conteudo = f.read()
    assert 'gunicorn app:app' in conteudo
    assert not re.search(r'--logger-class|--access-logformat', conteudo)
    for alvo in re.findall(r'(?:\s-c|--config)[\s=]+(\S+)', conteudo):
        assert alvo.strip('"\'') in ('gunicorn.conf.py', './gunicorn.conf.py'), alvo


@pytest.mark.parametrize('comando,aceito', [
    ('gunicorn app:app --bind 0.0.0.0:$PORT', True),
    ('gunicorn app:app --config gunicorn.conf.py --bind 0.0.0.0:$PORT', True),
    ('gunicorn app:app -c ./gunicorn.conf.py', True),
    ('gunicorn app:app --config=gunicorn.conf.py', True),
    ('gunicorn app:app -c outro.py', False),
    ('gunicorn app:app --logger-class gunicorn.glogging.Logger', False),
])
def test_regra_do_comando_de_inicio(comando, aceito):
    proibido = bool(re.search(r'--logger-class|--access-logformat', comando))
    alvos = re.findall(r'(?:\s-c|--config)[\s=]+(\S+)', comando)
    valido = not proibido and all(a.strip('"\'') in ('gunicorn.conf.py', './gunicorn.conf.py') for a in alvos)
    assert valido is aceito
