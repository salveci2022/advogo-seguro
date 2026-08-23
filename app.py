# -*- coding: utf-8 -*-
"""
ADVOGO SEGURO — Sistema anti-golpe do falso advogado
SPYNET Tecnologia Forense & Soluções Digitais Ltda

Stack: Flask + SQLAlchemy + PostgreSQL/SQLite + JWT + Hotmart Webhook
Padrão de arquitetura: igual SAE Fácil / NEXORA / PANIFICA PRO 360
"""

import os
import hashlib
import hmac
import json
import logging
import re
import secrets
import string
import smtplib
import ssl
import sqlite3
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, render_template, Response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from sqlalchemy import event, inspect, text, func
from sqlalchemy.orm import joinedload
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt
import stripe

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
import io as io_module


APP_VERSION = os.environ.get('APP_VERSION', '1.1.0').strip() or '1.1.0'


def agora_utc():
    """UTC sem timezone para manter compatibilidade com colunas DateTime atuais."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _env_bool(nome, padrao=False):
    valor = os.environ.get(nome)
    if valor is None:
        return bool(padrao)
    return valor.strip().lower() in {'1', 'true', 'yes', 'on'}

# ──────────────────────────────────────────────
# CONFIGURAÇÃO BASE
# ──────────────────────────────────────────────

app = Flask(__name__)

if not app.logger.handlers:
    logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

IS_PRODUCTION = bool(os.environ.get('RENDER') or os.environ.get('FLASK_ENV') == 'production')

# O frontend oficial usa a mesma origem da API. CORS fica fechado por padrão;
# só é habilitado quando ALLOWED_ORIGINS é explicitamente configurado.
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '').strip()
if ALLOWED_ORIGINS:
    origins = [o.strip() for o in ALLOWED_ORIGINS.split(',') if o.strip()]
    CORS(app, origins=origins, supports_credentials=True)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'troque-isso-em-producao')
app.config['JWT_SECRET'] = os.environ.get('JWT_SECRET', 'troque-isso-tambem')

if IS_PRODUCTION and (
    app.config['SECRET_KEY'] == 'troque-isso-em-producao' or
    app.config['JWT_SECRET'] == 'troque-isso-tambem'
):
    raise RuntimeError(
        'SECRET_KEY / JWT_SECRET não configurados em produção! '
        'Defina essas variáveis de ambiente antes de iniciar o servidor.'
    )

DATABASE_URL_ENV = os.environ.get('DATABASE_URL', '').strip()


def _validar_database_url_infra(database_url, is_production):
    """Impede que produção suba sem banco persistente configurado."""
    url = (database_url or '').strip()
    if not is_production:
        return url or 'sqlite:///advogo_seguro.db'
    if not url:
        raise RuntimeError(
            'DATABASE_URL não configurada em produção. '
            'O ADVOGO SEGURO não inicia para evitar uso acidental de SQLite local.'
        )
    normalizada = url.lower()
    if normalizada.startswith('sqlite:'):
        raise RuntimeError(
            'SQLite local não é permitido em produção. Configure PostgreSQL em DATABASE_URL.'
        )
    if not (
        normalizada.startswith('postgresql://')
        or normalizada.startswith('postgres://')
    ):
        raise RuntimeError('DATABASE_URL de produção deve apontar para PostgreSQL.')
    return url


DATABASE_URL = _validar_database_url_infra(DATABASE_URL_ENV, IS_PRODUCTION)
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'pool_pre_ping': True}

@event.listens_for(Engine, 'connect')
def _ativar_foreign_keys_sqlite(dbapi_connection, connection_record):
    """Ativa integridade referencial em toda conexão SQLite."""
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute('PRAGMA foreign_keys=ON')
        cursor.close()

db = SQLAlchemy(app)

ADMIN_SECRET = os.environ.get('ADMIN_SECRET', '').strip()
HOTMART_WEBHOOK_TOKEN = os.environ.get('HOTMART_WEBHOOK_TOKEN', '').strip()
HOTMART_PLAN_MAP_RAW = os.environ.get('HOTMART_PLAN_MAP', '').strip()
COMMERCIAL_WHATSAPP = re.sub(r'\D', '', os.environ.get('COMMERCIAL_WHATSAPP', ''))
COMMERCIAL_EMAIL = os.environ.get('COMMERCIAL_EMAIL', '').strip()
COMMERCIAL_FLOW_ENABLED = _env_bool('COMMERCIAL_FLOW_ENABLED', IS_PRODUCTION)
TRIAL_DIAS = int(os.environ.get('TRIAL_DIAS', '2'))
EMAIL_CONFIRMATION_TTL_MINUTES = int(os.environ.get('EMAIL_CONFIRMATION_TTL_MINUTES', '15'))
STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', '').strip()
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', '').strip()
STRIPE_PRICE_MAP_RAW = os.environ.get('STRIPE_PRICE_MAP', '').strip()
RESET_TOKEN_TTL_MINUTOS = 30
CONTATO_SEGURO_TTL_MINUTOS = int(os.environ.get('CONTATO_SEGURO_TTL_MINUTOS', '10'))
JWT_TTL_HORAS = int(os.environ.get('JWT_TTL_HORAS', '12'))
JWT_ISSUER = 'advogo-seguro'
AUTH_COOKIE_NAME = 'advogo_seguro_auth'
CSRF_COOKIE_NAME = 'advogo_seguro_csrf'
SENHA_MIN_CARACTERES = int(os.environ.get('SENHA_MIN_CARACTERES', '10'))

# Recuperação de senha por e-mail (SMTP genérico, sem dependência externa).
SMTP_HOST = os.environ.get('SMTP_HOST', '').strip()
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER', '').strip()
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
SMTP_FROM = os.environ.get('SMTP_FROM', SMTP_USER).strip()
SMTP_SECURITY = os.environ.get('SMTP_SECURITY', 'tls').strip().lower()  # tls | ssl | none
PUBLIC_BASE_URL = os.environ.get('PUBLIC_BASE_URL', '').strip().rstrip('/')

PRIVACY_CONTACT_EMAIL = os.environ.get('PRIVACY_CONTACT_EMAIL', '').strip()
LGPD_RETENCAO_LOGS_DIAS = int(os.environ.get('LGPD_RETENCAO_LOGS_DIAS', '0'))
if LGPD_RETENCAO_LOGS_DIAS < 0:
    raise RuntimeError('LGPD_RETENCAO_LOGS_DIAS não pode ser negativo.')
if TRIAL_DIAS != 2:
    raise RuntimeError('TRIAL_DIAS deve permanecer em 2 conforme a regra comercial vigente.')
if EMAIL_CONFIRMATION_TTL_MINUTES < 5 or EMAIL_CONFIRMATION_TTL_MINUTES > 60:
    raise RuntimeError('EMAIL_CONFIRMATION_TTL_MINUTES deve ficar entre 5 e 60 minutos.')

stripe.api_key = STRIPE_SECRET_KEY or None


# ──────────────────────────────────────────────
# PLANOS COMERCIAIS
# ──────────────────────────────────────────────
# Usa as colunas já existentes em escritorios (plano e plano_expira), portanto
# esta integração NÃO cria nem remove colunas do banco de dados.
PLANOS_ADVOGO_SEGURO = {
    'trial': {
        'nome': 'Período de Teste',
        'preco_mensal': 0.00,
        'implantacao': 0.00,
        'limite_advogados': 1,
    },
    'profissional': {
        'nome': 'Proteção Profissional',
        'preco_mensal': 179.00,
        'implantacao': 297.00,
        'limite_advogados': 1,
    },
    'escritorio': {
        'nome': 'Escritório Protegido',
        'preco_mensal': 497.00,
        'implantacao': 697.00,
        'limite_advogados': 5,
    },
    'blindagem': {
        'nome': 'Blindagem Jurídica',
        'preco_mensal': 997.00,
        'implantacao': 1497.00,
        'limite_advogados': 20,
    },
    'corporativo': {
        'nome': 'Corporativo',
        'preco_mensal': 1597.00,
        'implantacao': None,
        'limite_advogados': None,
    },
}

# Compatibilidade com contas antigas. Não altera automaticamente o valor salvo
# no banco; apenas aplica a regra equivalente no sistema novo.
PLANOS_LEGADOS = {
    'pro': 'escritorio',
    'enterprise': 'corporativo',
}


PLANO_INATIVO = {
    'nome': 'Plano Inativo',
    'preco_mensal': None,
    'implantacao': None,
    'limite_advogados': 0,
}


def _carregar_mapa_hotmart(valor):
    if not (valor or '').strip():
        return {}
    try:
        bruto = json.loads(valor)
    except json.JSONDecodeError as exc:
        raise RuntimeError('HOTMART_PLAN_MAP deve ser um JSON válido.') from exc
    if not isinstance(bruto, dict):
        raise RuntimeError('HOTMART_PLAN_MAP deve ser um objeto JSON.')
    mapa = {}
    for produto_id, codigo in bruto.items():
        produto_id = str(produto_id).strip()
        codigo = str(codigo).strip().lower()
        codigo = PLANOS_LEGADOS.get(codigo, codigo)
        if not produto_id or codigo not in PLANOS_ADVOGO_SEGURO or codigo == 'trial':
            raise RuntimeError(
                'HOTMART_PLAN_MAP contém produto/plano inválido. '
                'Use apenas planos pagos do ADVOGO SEGURO.'
            )
        mapa[produto_id] = codigo
    return mapa


HOTMART_PLAN_MAP = _carregar_mapa_hotmart(HOTMART_PLAN_MAP_RAW)


def _carregar_mapa_stripe(valor):
    if not (valor or '').strip():
        return {}
    try:
        bruto = json.loads(valor)
    except json.JSONDecodeError as exc:
        raise RuntimeError('STRIPE_PRICE_MAP deve ser um JSON válido.') from exc
    if not isinstance(bruto, dict):
        raise RuntimeError('STRIPE_PRICE_MAP deve ser um objeto JSON.')

    mapa = {}
    for codigo_bruto, precos_brutos in bruto.items():
        codigo = PLANOS_LEGADOS.get(str(codigo_bruto).strip().lower(), str(codigo_bruto).strip().lower())
        if codigo not in PLANOS_ADVOGO_SEGURO or codigo in {'trial', 'corporativo'}:
            raise RuntimeError(
                'STRIPE_PRICE_MAP aceita somente profissional, escritorio e blindagem.'
            )
        if not isinstance(precos_brutos, dict):
            raise RuntimeError(f'Preços Stripe inválidos para o plano {codigo}.')
        mensal = str(precos_brutos.get('mensal') or '').strip()
        implantacao = str(precos_brutos.get('implantacao') or '').strip()
        if not mensal.startswith('price_') or not implantacao.startswith('price_'):
            raise RuntimeError(
                f'O plano {codigo} precisa dos IDs Stripe mensal e implantacao.'
            )
        mapa[codigo] = {'mensal': mensal, 'implantacao': implantacao}
    return mapa


STRIPE_PRICE_MAP = _carregar_mapa_stripe(STRIPE_PRICE_MAP_RAW)


def normalizar_codigo_plano(codigo):
    codigo = (codigo or 'trial').strip().lower()
    return PLANOS_LEGADOS.get(codigo, codigo)


def obter_config_plano(codigo):
    codigo_normalizado = normalizar_codigo_plano(codigo)
    if codigo_normalizado in PLANOS_ADVOGO_SEGURO:
        return codigo_normalizado, PLANOS_ADVOGO_SEGURO[codigo_normalizado]
    return codigo_normalizado, PLANO_INATIVO

# Upload de foto do advogado (Sprint 3)
UPLOAD_EXTENSOES_PERMITIDAS = {'jpg', 'jpeg', 'png', 'webp'}
UPLOAD_TAMANHO_MAXIMO_BYTES = 3 * 1024 * 1024  # 3 MB
UPLOAD_PASTA_ADVOGADOS = os.path.join(app.root_path, 'static', 'uploads', 'advogados')
os.makedirs(UPLOAD_PASTA_ADVOGADOS, exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = UPLOAD_TAMANHO_MAXIMO_BYTES


# ──────────────────────────────────────────────
# TRATAMENTO GLOBAL DE ERROS
# ──────────────────────────────────────────────
# Qualquer exceção não tratada explicitamente numa rota cai aqui: o erro
# técnico completo vai para o log do servidor, e o cliente recebe uma
# mensagem genérica e segura (nunca detalhes de banco/stacktrace).

@app.errorhandler(HTTPException)
def tratar_http_exception(erro):
    resposta = erro.get_response()
    resposta.data = jsonify({'erro': erro.description or 'Requisição inválida'}).get_data()
    resposta.content_type = 'application/json'
    return resposta


@app.errorhandler(Exception)
def tratar_erro_inesperado(erro):
    db.session.rollback()
    app.logger.exception('Erro inesperado não tratado: %s', erro)
    return jsonify({'erro': 'Não foi possível concluir a operação. Tente novamente em instantes.'}), 500


@app.after_request
def aplicar_headers_seguranca(resposta):
    # O projeto ainda possui scripts/estilos inline em templates legados;
    # por isso a CSP mantém unsafe-inline temporariamente, mas fecha origens externas.
    csp = (
        "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; "
        "form-action 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'"
    )
    resposta.headers['Content-Security-Policy'] = csp
    resposta.headers['X-Frame-Options'] = 'DENY'
    resposta.headers['X-Content-Type-Options'] = 'nosniff'
    # Existem tokens em URLs de reset/link seguro; nunca os envie como Referer.
    resposta.headers['Referrer-Policy'] = 'no-referrer'
    resposta.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=(), usb=()'
    if IS_PRODUCTION:
        resposta.headers['Strict-Transport-Security'] = 'max-age=31536000'
    if request.path.startswith('/api/publico/foto-advogado/'):
        # O token muda a cada nova foto; por isso a resposta pode ser cacheada sem
        # risco de manter uma versão antiga após a substituição.
        resposta.headers['Cache-Control'] = 'public, max-age=604800, immutable'
    elif request.path.startswith('/api/') or request.path.startswith('/webhook/'):
        resposta.headers['Cache-Control'] = 'no-store'
    elif IS_PRODUCTION and request.path.startswith('/static/'):
        # Arquivos de upload recebem nome único a cada troca, então podem ser
        # cacheados por mais tempo. CSS/JS mantêm cache curto para permitir deploys.
        if request.path.startswith('/static/uploads/'):
            resposta.headers['Cache-Control'] = 'public, max-age=604800, immutable'
        else:
            resposta.headers['Cache-Control'] = 'public, max-age=3600'
    return resposta


# ──────────────────────────────────────────────
# RATE LIMITING SIMPLES (proteção de login)
# ──────────────────────────────────────────────
# Implementação em memória — suficiente para uma única instância.
# Em produção com múltiplos workers, considere Redis (flask-limiter + storage_uri).

_tentativas_login = {}  # chave: (ip, identificador) -> [timestamps]
MAX_TENTATIVAS = 5
JANELA_BLOQUEIO_SEGUNDOS = 300  # 5 minutos


def _chave_rate_limit(identificador):
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or 'desconhecido').split(',')[0].strip()
    return f'{ip}:{identificador.lower()}'


def verificar_rate_limit(identificador):
    """Retorna (permitido: bool, segundos_restantes: int)."""
    chave = _chave_rate_limit(identificador)
    agora = agora_utc().timestamp()
    tentativas = [t for t in _tentativas_login.get(chave, []) if agora - t < JANELA_BLOQUEIO_SEGUNDOS]
    if tentativas:
        _tentativas_login[chave] = tentativas
    else:
        _tentativas_login.pop(chave, None)

    # Limpeza oportunista evita crescimento indefinido com identificadores únicos.
    if len(_tentativas_login) > 1000:
        for chave_antiga, valores in list(_tentativas_login.items()):
            validas = [t for t in valores if agora - t < JANELA_BLOQUEIO_SEGUNDOS]
            if validas:
                _tentativas_login[chave_antiga] = validas
            else:
                _tentativas_login.pop(chave_antiga, None)

    if len(tentativas) >= MAX_TENTATIVAS:
        restante = int(JANELA_BLOQUEIO_SEGUNDOS - (agora - tentativas[0]))
        return False, max(restante, 1)
    return True, 0


def registrar_tentativa_falha(identificador):
    chave = _chave_rate_limit(identificador)
    _tentativas_login.setdefault(chave, []).append(agora_utc().timestamp())


def limpar_tentativas(identificador):
    chave = _chave_rate_limit(identificador)
    _tentativas_login.pop(chave, None)


_tentativas_acoes = {}

def verificar_limite_acao(identificador, max_tentativas=5, janela_segundos=900):
    """Rate limit simples para reset e rotas públicas sensíveis."""
    chave = _chave_rate_limit(f'acao:{identificador}')
    agora = agora_utc().timestamp()
    valores = [t for t in _tentativas_acoes.get(chave, []) if agora - t < janela_segundos]
    if len(valores) >= max_tentativas:
        restante = int(janela_segundos - (agora - valores[0]))
        _tentativas_acoes[chave] = valores
        return False, max(restante, 1)
    valores.append(agora)
    _tentativas_acoes[chave] = valores
    if len(_tentativas_acoes) > 2000:
        for k, eventos in list(_tentativas_acoes.items()):
            recentes = [t for t in eventos if agora - t < janela_segundos]
            if recentes:
                _tentativas_acoes[k] = recentes
            else:
                _tentativas_acoes.pop(k, None)
    return True, 0


# ──────────────────────────────────────────────
# MODELOS
# ──────────────────────────────────────────────

class Escritorio(db.Model):
    __tablename__ = 'escritorios'
    __table_args__ = (
        db.Index('ix_escritorios_reset_token', 'reset_token'),
        db.Index('ix_escritorios_email_confirmacao_token', 'email_confirmacao_token_hash'),
        db.Index('ux_escritorios_stripe_customer', 'stripe_customer_id', unique=True),
        db.Index('ux_escritorios_stripe_subscription', 'stripe_subscription_id', unique=True),
    )
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(200), nullable=False)
    tipo_pessoa = db.Column(db.String(2), default='pj', nullable=False)  # pf | pj
    cpf = db.Column(db.String(14))
    oab = db.Column(db.String(30))
    cnpj = db.Column(db.String(20))
    email = db.Column(db.String(200), unique=True, nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)
    plano = db.Column(db.String(20), default='trial')  # trial | pro | enterprise
    plano_expira = db.Column(db.DateTime)
    criado_em = db.Column(db.DateTime, default=agora_utc)
    reset_token = db.Column(db.String(100))
    reset_token_expira = db.Column(db.DateTime)
    email_confirmacao_obrigatoria = db.Column(db.Boolean, default=False, nullable=False)
    email_confirmado_em = db.Column(db.DateTime)
    email_confirmacao_token_hash = db.Column(db.String(64))
    email_confirmacao_expira = db.Column(db.DateTime)
    plano_pretendido = db.Column(db.String(20))
    assinatura_status = db.Column(db.String(30), default='sem_assinatura', nullable=False)
    stripe_customer_id = db.Column(db.String(120))
    stripe_subscription_id = db.Column(db.String(120))
    stripe_checkout_session_id = db.Column(db.String(120))
    trial_utilizado_em = db.Column(db.DateTime)
    taxa_implantacao_paga_em = db.Column(db.DateTime)

    advogados = db.relationship('Advogado', backref='escritorio', lazy=True)
    processos = db.relationship('Processo', backref='escritorio', lazy=True)

    def plano_ativo(self):
        codigo_original = (self.plano or 'trial').strip().lower()
        codigo_normalizado = normalizar_codigo_plano(codigo_original)

        if self.stripe_subscription_id and self.assinatura_status in {
            'incomplete', 'incomplete_expired', 'past_due', 'unpaid', 'paused', 'canceled'
        }:
            return False

        if codigo_normalizado == 'trial':
            return bool(self.plano_expira and self.plano_expira > agora_utc())

        if codigo_normalizado not in PLANOS_ADVOGO_SEGURO:
            return False

        # Contas legadas "pro" e "enterprise" continuam ativas para evitar
        # bloqueio inesperado de clientes já cadastrados.
        if codigo_original in PLANOS_LEGADOS:
            return True

        # Nos planos atuais, data vazia significa contrato sem vencimento
        # automático. Quando houver data, ela precisa estar no futuro.
        return self.plano_expira is None or self.plano_expira > agora_utc()

    def config_plano(self):
        return obter_config_plano(self.plano)

    def limite_advogados(self):
        _, config = self.config_plano()
        return config['limite_advogados']

    def email_confirmado(self):
        return not self.email_confirmacao_obrigatoria or bool(self.email_confirmado_em)


class Advogado(db.Model):
    __tablename__ = 'advogados'
    __table_args__ = (
        db.Index('ix_advogados_escritorio_ativo', 'escritorio_id', 'ativo'),
        db.Index('ix_advogados_escritorio_oab', 'escritorio_id', 'oab'),
    )
    id = db.Column(db.Integer, primary_key=True)
    escritorio_id = db.Column(db.Integer, db.ForeignKey('escritorios.id', ondelete='CASCADE'), nullable=False)
    nome = db.Column(db.String(200), nullable=False)
    oab = db.Column(db.String(30))
    telefone_oficial = db.Column(db.String(20), nullable=False)
    # foto_url continua existindo por compatibilidade com URLs HTTPS e dados legados.
    # Uploads feitos pelo sistema passam a ser persistidos no banco, evitando
    # dependência do filesystem efêmero do serviço web.
    foto_url = db.Column(db.String(500))
    foto_blob = db.Column(db.LargeBinary)
    foto_mime = db.Column(db.String(50))
    foto_token = db.Column(db.String(64), unique=True)
    ativo = db.Column(db.Boolean, default=True, nullable=False)
    criado_em = db.Column(db.DateTime, default=agora_utc)


class Cliente(db.Model):
    __tablename__ = 'clientes'
    __table_args__ = (
        db.Index('ix_clientes_reset_token', 'reset_token'),
    )
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(200), nullable=False)
    telefone = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(200))
    senha_hash = db.Column(db.String(200), nullable=False)
    ativo = db.Column(db.Boolean, default=True, nullable=False)
    criado_em = db.Column(db.DateTime, default=agora_utc)
    reset_token = db.Column(db.String(100))
    reset_token_expira = db.Column(db.DateTime)

    verificacoes = db.relationship('Verificacao', backref='cliente', lazy=True, cascade='all, delete-orphan')


class Processo(db.Model):
    __tablename__ = 'processos'
    __table_args__ = (
        db.Index('ix_processos_escritorio_criado', 'escritorio_id', 'criado_em'),
        db.Index('ix_processos_cliente_status', 'cliente_id', 'status'),
        db.Index('ix_processos_advogado_escritorio', 'advogado_id', 'escritorio_id'),
    )
    id = db.Column(db.Integer, primary_key=True)
    escritorio_id = db.Column(db.Integer, db.ForeignKey('escritorios.id', ondelete='CASCADE'), nullable=False)
    advogado_id = db.Column(db.Integer, db.ForeignKey('advogados.id', ondelete='CASCADE'), nullable=False)
    cliente_id = db.Column(db.Integer, db.ForeignKey('clientes.id', ondelete='CASCADE'), nullable=False)
    codigo_unico = db.Column(db.String(12), unique=True, nullable=False)
    numero_processo = db.Column(db.String(60))
    descricao = db.Column(db.String(300))
    status = db.Column(db.String(20), default='ativo')  # ativo | arquivado
    criado_em = db.Column(db.DateTime, default=agora_utc)
    token_cliente = db.Column(db.String(100), unique=True)  # link seguro sem login (Sprint 3)

    advogado = db.relationship('Advogado', backref='processos', lazy=True)
    cliente = db.relationship('Cliente', backref='processos', lazy=True)
    tentativas = db.relationship('TentativaContato', backref='processo', lazy=True, cascade='all, delete-orphan')


class Verificacao(db.Model):
    __tablename__ = 'verificacoes'
    __table_args__ = (
        db.Index('ix_verificacoes_cliente_criado', 'cliente_id', 'criado_em'),
    )
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('clientes.id', ondelete='CASCADE'), nullable=False)
    numero_consultado = db.Column(db.String(20), nullable=False)
    codigo_consultado = db.Column(db.String(12))
    resultado = db.Column(db.String(20))  # confirmado | nao_encontrado | numero_diferente
    criado_em = db.Column(db.DateTime, default=agora_utc)


class TentativaContato(db.Model):
    __tablename__ = 'tentativas_contato'
    __table_args__ = (
        db.Index('ix_tentativas_processo_criado', 'processo_id', 'criado_em'),
    )
    id = db.Column(db.Integer, primary_key=True)
    processo_id = db.Column(db.Integer, db.ForeignKey('processos.id', ondelete='CASCADE'), nullable=False)
    numero_suspeito = db.Column(db.String(20))
    canal = db.Column(db.String(30))  # whatsapp | ligacao | videochamada | email
    descricao = db.Column(db.String(500))
    confirmado_golpe = db.Column(db.Boolean, default=False)
    criado_em = db.Column(db.DateTime, default=agora_utc)


class ContatoSeguro(db.Model):
    """
    'Contato Seguro ADVOGO' / Código de Contato Autorizado (CCA).

    O escritório gera este código ANTES de ligar/mensagear o cliente.
    O cliente nunca recebe nem digita o código — ele apenas consulta,
    em canal separado, se existe um contato autorizado ativo no momento.
    """
    __tablename__ = 'contatos_seguros'
    __table_args__ = (
        db.Index('ix_contatos_escritorio_criado', 'escritorio_id', 'criado_em'),
        db.Index('ix_contatos_cliente_status_expira', 'cliente_id', 'status', 'expira_em'),
        db.Index('ix_contatos_processo_status_expira', 'processo_id', 'status', 'expira_em'),
        db.Index('ix_contatos_advogado', 'advogado_id'),
    )
    id = db.Column(db.Integer, primary_key=True)
    escritorio_id = db.Column(db.Integer, db.ForeignKey('escritorios.id', ondelete='CASCADE'), nullable=False)
    advogado_id = db.Column(db.Integer, db.ForeignKey('advogados.id', ondelete='CASCADE'), nullable=False)
    cliente_id = db.Column(db.Integer, db.ForeignKey('clientes.id', ondelete='CASCADE'), nullable=False)
    processo_id = db.Column(db.Integer, db.ForeignKey('processos.id', ondelete='CASCADE'), nullable=True)
    codigo_cca = db.Column(db.String(20), unique=True, nullable=False)
    canal = db.Column(db.String(30), nullable=False)  # whatsapp | ligacao | videochamada | email
    status = db.Column(db.String(20), default='ativo')  # ativo | expirado | usado | cancelado
    expira_em = db.Column(db.DateTime, nullable=False)
    usado_em = db.Column(db.DateTime)
    cancelado_em = db.Column(db.DateTime)
    observacao = db.Column(db.String(300))
    criado_em = db.Column(db.DateTime, default=agora_utc)

    escritorio = db.relationship('Escritorio')
    advogado = db.relationship('Advogado')
    cliente = db.relationship('Cliente')
    processo = db.relationship('Processo')
    logs = db.relationship('ContatoSeguroLog', backref='contato_seguro', lazy=True, cascade='all, delete-orphan')

    def status_atual(self):
        """Recalcula o status no momento da leitura, sem nunca tratar um código vencido como válido."""
        if self.status in ('cancelado', 'expirado'):
            return self.status
        if self.expira_em < agora_utc():
            return 'expirado'
        return self.status


class ContatoSeguroLog(db.Model):
    """Log de auditoria de toda consulta feita pelo cliente (mesmo quando não há contato ativo)."""
    __tablename__ = 'contatos_seguros_logs'
    __table_args__ = (
        db.Index('ix_contatos_logs_cliente_criado', 'cliente_id', 'criado_em'),
        db.Index('ix_contatos_logs_contato', 'contato_seguro_id'),
    )
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('clientes.id', ondelete='CASCADE'), nullable=False)
    contato_seguro_id = db.Column(db.Integer, db.ForeignKey('contatos_seguros.id', ondelete='CASCADE'), nullable=True)
    encontrado_ativo = db.Column(db.Boolean, default=False)
    ip = db.Column(db.String(60))
    criado_em = db.Column(db.DateTime, default=agora_utc)


class AcessoPublicoLog(db.Model):
    """Auditoria de acesso ao link público do cliente (/cliente/seguro/<token>) — Sprint 3."""
    __tablename__ = 'acessos_publicos_logs'
    __table_args__ = (
        db.Index('ix_acessos_processo_criado', 'processo_id', 'criado_em'),
    )
    id = db.Column(db.Integer, primary_key=True)
    processo_id = db.Column(db.Integer, db.ForeignKey('processos.id', ondelete='CASCADE'), nullable=True)
    acao = db.Column(db.String(40))  # visualizou | verificou | alerta_pix | nao_reconheco
    ip = db.Column(db.String(60))
    criado_em = db.Column(db.DateTime, default=agora_utc)


class SolicitacaoPrivacidade(db.Model):
    """Fila auditável de solicitações de titulares sem copiar nome/e-mail/telefone."""
    __tablename__ = 'solicitacoes_privacidade'
    __table_args__ = (
        db.Index('ix_privacidade_referencia_criado', 'referencia_titular', 'criado_em'),
        db.Index('ix_privacidade_status_criado', 'status', 'criado_em'),
    )
    id = db.Column(db.Integer, primary_key=True)
    referencia_titular = db.Column(db.String(64), nullable=False)
    titular_tipo = db.Column(db.String(20), nullable=False)
    tipo = db.Column(db.String(40), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='recebida')
    detalhes = db.Column(db.String(500))
    criado_em = db.Column(db.DateTime, default=agora_utc, nullable=False)
    atualizado_em = db.Column(db.DateTime, default=agora_utc, nullable=False)


class EventoWebhook(db.Model):
    """Idempotência de webhooks comerciais sem armazenar dados pessoais do comprador."""
    __tablename__ = 'eventos_webhook'
    __table_args__ = (
        db.UniqueConstraint('provedor', 'event_id', name='uq_webhook_provedor_evento'),
        db.Index('ix_webhook_provedor_criado', 'provedor', 'criado_em'),
    )
    id = db.Column(db.Integer, primary_key=True)
    provedor = db.Column(db.String(30), nullable=False)
    event_id = db.Column(db.String(120), nullable=False)
    evento = db.Column(db.String(80), nullable=False)
    produto_id = db.Column(db.String(120))
    plano = db.Column(db.String(30))
    resultado = db.Column(db.String(40), nullable=False, default='processado')
    criado_em = db.Column(db.DateTime, default=agora_utc, nullable=False)


# ──────────────────────────────────────────────
# MIGRAÇÃO SEGURA (adiciona colunas novas sem apagar dados existentes)
# ──────────────────────────────────────────────
# db.create_all() só cria tabelas que ainda não existem — nunca altera uma
# tabela já existente no Postgres do Render. Como este projeto não usa
# Alembic/Flask-Migrate, novas colunas precisam ser adicionadas manualmente
# aqui, de forma idempotente (só roda se a coluna ainda não existir) e sem
# nenhuma operação destrutiva.

def _garantir_colunas_novas():
    inspetor = inspect(db.engine)
    tipo_binario = 'BYTEA' if db.engine.dialect.name == 'postgresql' else 'BLOB'
    colunas_necessarias = [
        ('advogados', 'ativo', 'BOOLEAN NOT NULL DEFAULT TRUE'),
        ('advogados', 'foto_blob', tipo_binario),
        ('advogados', 'foto_mime', 'VARCHAR(50)'),
        ('advogados', 'foto_token', 'VARCHAR(64)'),
        ('clientes', 'ativo', 'BOOLEAN NOT NULL DEFAULT TRUE'),
        ('escritorios', 'tipo_pessoa', "VARCHAR(2) NOT NULL DEFAULT 'pj'"),
        ('escritorios', 'cpf', 'VARCHAR(14)'),
        ('escritorios', 'oab', 'VARCHAR(30)'),
        ('escritorios', 'email_confirmacao_obrigatoria', 'BOOLEAN NOT NULL DEFAULT FALSE'),
        ('escritorios', 'email_confirmado_em', 'TIMESTAMP'),
        ('escritorios', 'email_confirmacao_token_hash', 'VARCHAR(64)'),
        ('escritorios', 'email_confirmacao_expira', 'TIMESTAMP'),
        ('escritorios', 'plano_pretendido', 'VARCHAR(20)'),
        ('escritorios', 'assinatura_status', "VARCHAR(30) NOT NULL DEFAULT 'sem_assinatura'"),
        ('escritorios', 'stripe_customer_id', 'VARCHAR(120)'),
        ('escritorios', 'stripe_subscription_id', 'VARCHAR(120)'),
        ('escritorios', 'stripe_checkout_session_id', 'VARCHAR(120)'),
        ('escritorios', 'trial_utilizado_em', 'TIMESTAMP'),
        ('escritorios', 'taxa_implantacao_paga_em', 'TIMESTAMP'),
    ]
    for tabela, coluna, definicao_sql in colunas_necessarias:
        if not inspetor.has_table(tabela):
            continue
        colunas_existentes = {c['name'] for c in inspetor.get_columns(tabela)}
        if coluna in colunas_existentes:
            continue
        with db.engine.begin() as conexao:
            conexao.execute(text(f'ALTER TABLE {tabela} ADD COLUMN {coluna} {definicao_sql}'))
        print(f'[MIGRACAO] Coluna "{coluna}" adicionada em "{tabela}".')


def _garantir_indices_banco():
    """Cria índices idempotentes em bancos legados sem apagar ou reescrever dados."""
    inspetor = inspect(db.engine)
    indices = [
        ('escritorios', 'ix_escritorios_reset_token', 'reset_token'),
        ('escritorios', 'ix_escritorios_email_confirmacao_token', 'email_confirmacao_token_hash'),
        ('advogados', 'ix_advogados_escritorio_ativo', 'escritorio_id, ativo'),
        ('advogados', 'ix_advogados_escritorio_oab', 'escritorio_id, oab'),
        ('clientes', 'ix_clientes_reset_token', 'reset_token'),
        ('processos', 'ix_processos_escritorio_criado', 'escritorio_id, criado_em'),
        ('processos', 'ix_processos_cliente_status', 'cliente_id, status'),
        ('processos', 'ix_processos_advogado_escritorio', 'advogado_id, escritorio_id'),
        ('verificacoes', 'ix_verificacoes_cliente_criado', 'cliente_id, criado_em'),
        ('tentativas_contato', 'ix_tentativas_processo_criado', 'processo_id, criado_em'),
        ('contatos_seguros', 'ix_contatos_escritorio_criado', 'escritorio_id, criado_em'),
        ('contatos_seguros', 'ix_contatos_cliente_status_expira', 'cliente_id, status, expira_em'),
        ('contatos_seguros', 'ix_contatos_processo_status_expira', 'processo_id, status, expira_em'),
        ('contatos_seguros', 'ix_contatos_advogado', 'advogado_id'),
        ('contatos_seguros_logs', 'ix_contatos_logs_cliente_criado', 'cliente_id, criado_em'),
        ('contatos_seguros_logs', 'ix_contatos_logs_contato', 'contato_seguro_id'),
        ('acessos_publicos_logs', 'ix_acessos_processo_criado', 'processo_id, criado_em'),
        ('solicitacoes_privacidade', 'ix_privacidade_referencia_criado', 'referencia_titular, criado_em'),
        ('solicitacoes_privacidade', 'ix_privacidade_status_criado', 'status, criado_em'),
        ('eventos_webhook', 'ix_webhook_provedor_criado', 'provedor, criado_em'),
    ]
    with db.engine.begin() as conexao:
        for tabela, nome, colunas in indices:
            if inspetor.has_table(tabela):
                conexao.execute(text(f'CREATE INDEX IF NOT EXISTS "{nome}" ON "{tabela}" ({colunas})'))

        if inspetor.has_table('advogados'):
            conexao.execute(text(
                'CREATE UNIQUE INDEX IF NOT EXISTS ux_advogados_foto_token ON advogados (foto_token)'
            ))

        if inspetor.has_table('clientes'):
            duplicados = conexao.execute(text(
                'SELECT COUNT(*) FROM ('
                'SELECT telefone FROM clientes WHERE telefone IS NOT NULL '
                'GROUP BY telefone HAVING COUNT(*) > 1'
                ') AS duplicados'
            )).scalar() or 0
            if duplicados == 0:
                conexao.execute(text(
                    'CREATE UNIQUE INDEX IF NOT EXISTS ux_clientes_telefone ON clientes (telefone)'
                ))
            else:
                app.logger.error(
                    '[BANCO] Existem %s telefone(s) duplicado(s) em clientes; '
                    'o índice único não foi criado. Corrija as duplicidades antes do deploy.',
                    duplicados,
                )

        if inspetor.has_table('escritorios'):
            conexao.execute(text(
                'CREATE UNIQUE INDEX IF NOT EXISTS ux_escritorios_stripe_customer '
                'ON escritorios (stripe_customer_id)'
            ))
            conexao.execute(text(
                'CREATE UNIQUE INDEX IF NOT EXISTS ux_escritorios_stripe_subscription '
                'ON escritorios (stripe_subscription_id)'
            ))


def _verificar_integridade_banco_local():
    """Falha cedo se um SQLite local tiver corrupção física ou referências órfãs."""
    if db.engine.dialect.name != 'sqlite':
        return
    with db.engine.connect() as conexao:
        integridade = conexao.execute(text('PRAGMA integrity_check')).scalar()
        orfaos = conexao.execute(text('PRAGMA foreign_key_check')).fetchall()
    if integridade != 'ok' or orfaos:
        raise RuntimeError('Banco SQLite falhou na verificação de integridade/referências.')


# ──────────────────────────────────────────────
# EXCLUSÃO SEGURA EM CASCATA
# ──────────────────────────────────────────────
# Cada função apaga primeiro os registros filhos (na ordem correta para não
# violar nenhuma chave estrangeira) e só depois o registro principal.
# Nenhuma função aqui faz commit — quem chama controla a transação e pode
# fazer rollback caso algo dê errado no meio do processo.

def _excluir_contatos_seguros_em_lote(contatos_seguros_ids):
    """Apaga um conjunto de Contatos Seguros e os respectivos logs de auditoria."""
    if not contatos_seguros_ids:
        return
    ContatoSeguroLog.query.filter(
        ContatoSeguroLog.contato_seguro_id.in_(contatos_seguros_ids)
    ).delete(synchronize_session=False)
    ContatoSeguro.query.filter(
        ContatoSeguro.id.in_(contatos_seguros_ids)
    ).delete(synchronize_session=False)


def _excluir_processo_em_cascata(processo):
    """Apaga todos os registros filhos de um processo e, por fim, o processo."""
    contatos_ids = [c.id for c in ContatoSeguro.query.filter_by(processo_id=processo.id).all()]
    _excluir_contatos_seguros_em_lote(contatos_ids)
    TentativaContato.query.filter_by(processo_id=processo.id).delete(synchronize_session=False)
    AcessoPublicoLog.query.filter_by(processo_id=processo.id).delete(synchronize_session=False)
    db.session.delete(processo)


def _excluir_advogado_em_cascata(advogado, escritorio_id):
    """Apaga o advogado, todos os processos dele (com seus filhos) e Contatos
    Seguros vinculados diretamente a ele (sem processo associado)."""
    processos = Processo.query.filter_by(advogado_id=advogado.id, escritorio_id=escritorio_id).all()
    for processo in processos:
        _excluir_processo_em_cascata(processo)

    orfaos_ids = [
        c.id for c in ContatoSeguro.query.filter_by(advogado_id=advogado.id, processo_id=None).all()
    ]
    _excluir_contatos_seguros_em_lote(orfaos_ids)
    db.session.delete(advogado)


def _cliente_possui_processos_de_outro_escritorio(cliente_id, escritorio_id):
    return Processo.query.filter(
        Processo.cliente_id == cliente_id, Processo.escritorio_id != escritorio_id
    ).first() is not None


def _excluir_cliente_em_cascata(cliente, escritorio_id):
    """
    Apaga todos os processos (e filhos) que este escritório tem com o
    cliente. Só apaga o registro do Cliente em si se ele não pertencer
    também a outro escritório (mesmo telefone pode estar vinculado a mais
    de um escritório) — nesse caso preservamos o cliente e os dados do
    outro escritório intactos.

    Retorna True se o Cliente foi totalmente removido, False se foi apenas
    desvinculado deste escritório e preservado por pertencer a outro.
    """
    processos = Processo.query.filter_by(cliente_id=cliente.id, escritorio_id=escritorio_id).all()
    for processo in processos:
        _excluir_processo_em_cascata(processo)

    if _cliente_possui_processos_de_outro_escritorio(cliente.id, escritorio_id):
        return False

    orfaos_ids = [
        c.id for c in ContatoSeguro.query.filter_by(cliente_id=cliente.id, processo_id=None).all()
    ]
    _excluir_contatos_seguros_em_lote(orfaos_ids)
    ContatoSeguroLog.query.filter_by(cliente_id=cliente.id).delete(synchronize_session=False)
    Verificacao.query.filter_by(cliente_id=cliente.id).delete(synchronize_session=False)
    db.session.delete(cliente)
    return True


# ──────────────────────────────────────────────
# UTILITÁRIOS
# ──────────────────────────────────────────────

def hash_senha(senha):
    """Hash seguro com salt (PBKDF2-SHA256, via Werkzeug)."""
    return generate_password_hash(senha, method='pbkdf2:sha256', salt_length=16)


def verificar_senha(senha_hash_salva, senha_digitada):
    """
    Confere a senha contra o hash salvo.
    Compatível com hashes antigos em SHA-256 puro (sem salt) gerados antes
    desta atualização de segurança — eles são automaticamente re-hasheados
    para PBKDF2 no primeiro login correto.
    """
    if senha_hash_salva and len(senha_hash_salva) == 64 and ':' not in senha_hash_salva:
        # formato legado: sha256 hex puro
        return hashlib.sha256(senha_digitada.encode()).hexdigest() == senha_hash_salva
    try:
        return check_password_hash(senha_hash_salva, senha_digitada)
    except Exception:
        return False


def gerar_token_reset():
    """Retorna (token_bruto, token_hash). Apenas o hash é persistido no banco."""
    token = secrets.token_urlsafe(32)
    return token, hashlib.sha256(token.encode('utf-8')).hexdigest()


def hash_token_reset(token):
    return hashlib.sha256((token or '').encode('utf-8')).hexdigest()


def _versao_credencial(senha_hash):
    """Vincula o JWT ao hash atual da senha; trocar senha revoga tokens antigos."""
    return hashlib.sha256((senha_hash or '').encode('utf-8')).hexdigest()[:24]


def gerar_codigo_cca():
    """Gera um código curto único no formato CCA-NNNN, só visível ao escritório."""
    while True:
        numero = ''.join(secrets.choice(string.digits) for _ in range(4))
        codigo = f'CCA-{numero}'
        if not ContatoSeguro.query.filter_by(codigo_cca=codigo).first():
            return codigo


def gerar_codigo_unico():
    while True:
        codigo = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
        if not Processo.query.filter_by(codigo_unico=codigo).first():
            return codigo


def gerar_token(payload, senha_hash, horas=None):
    payload = dict(payload)
    agora = agora_utc()
    csrf = secrets.token_urlsafe(24)
    payload.update({
        'iat': agora,
        'exp': agora + timedelta(hours=horas or JWT_TTL_HORAS),
        'iss': JWT_ISSUER,
        'csrf': csrf,
        'cv': _versao_credencial(senha_hash),
    })
    token = jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')
    return token, csrf


def decodificar_token(token):
    try:
        return jwt.decode(
            token,
            app.config['JWT_SECRET'],
            algorithms=['HS256'],
            issuer=JWT_ISSUER,
            options={'require': ['exp', 'iat', 'iss', 'id', 'tipo', 'csrf', 'cv']}
        )
    except Exception:
        return None


def _token_da_requisicao():
    auth = request.headers.get('Authorization', '')
    if auth.startswith('Bearer '):
        token_bearer = auth[7:].strip()
        if token_bearer:
            return token_bearer, 'bearer'
    token_cookie = request.cookies.get(AUTH_COOKIE_NAME, '')
    if token_cookie:
        return token_cookie, 'cookie'
    return None, None


def _csrf_valido(dados, origem_token):
    if request.method in ('GET', 'HEAD', 'OPTIONS') or origem_token != 'cookie':
        return True
    esperado = str(dados.get('csrf') or '')
    cabecalho = request.headers.get('X-CSRF-Token', '')
    cookie = request.cookies.get(CSRF_COOKIE_NAME, '')
    return bool(esperado and cabecalho and cookie and
                hmac.compare_digest(esperado, cabecalho) and
                hmac.compare_digest(esperado, cookie))


def _resposta_com_sessao(dados_resposta, payload_jwt, senha_hash):
    token, csrf = gerar_token(payload_jwt, senha_hash)
    dados = dict(dados_resposta)
    # Compatibilidade para testes e integrações locais. Em produção o JWT nunca
    # é entregue ao JavaScript; fica somente em cookie HttpOnly.
    if not IS_PRODUCTION:
        dados['token'] = token
    resposta = jsonify(dados)
    max_age = JWT_TTL_HORAS * 3600
    resposta.set_cookie(
        AUTH_COOKIE_NAME, token, max_age=max_age, httponly=True,
        secure=IS_PRODUCTION, samesite='Strict', path='/'
    )
    resposta.set_cookie(
        CSRF_COOKIE_NAME, csrf, max_age=max_age, httponly=False,
        secure=IS_PRODUCTION, samesite='Strict', path='/'
    )
    return resposta


def _limpar_cookies_sessao(resposta):
    resposta.delete_cookie(AUTH_COOKIE_NAME, path='/', secure=IS_PRODUCTION, samesite='Strict')
    resposta.delete_cookie(CSRF_COOKIE_NAME, path='/', secure=IS_PRODUCTION, samesite='Strict')
    return resposta


def login_escritorio_obrigatorio(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token, origem = _token_da_requisicao()
        dados = decodificar_token(token) if token else None
        if not dados or dados.get('tipo') != 'escritorio':
            return jsonify({'erro': 'Não autenticado'}), 401
        escritorio = db.session.get(Escritorio, dados['id'])
        if not escritorio:
            return jsonify({'erro': 'Escritório não encontrado'}), 404
        if not hmac.compare_digest(str(dados.get('cv') or ''), _versao_credencial(escritorio.senha_hash)):
            return jsonify({'erro': 'Sessão expirada. Faça login novamente.'}), 401
        if not _csrf_valido(dados, origem):
            return jsonify({'erro': 'Requisição de segurança inválida. Atualize a página e tente novamente.'}), 403
        request.escritorio = escritorio
        request.auth_dados = dados
        return f(*args, **kwargs)
    return wrapper


def login_cliente_obrigatorio(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token, origem = _token_da_requisicao()
        dados = decodificar_token(token) if token else None
        if not dados or dados.get('tipo') != 'cliente':
            return jsonify({'erro': 'Não autenticado'}), 401
        cliente = db.session.get(Cliente, dados['id'])
        if not cliente:
            return jsonify({'erro': 'Cliente não encontrado'}), 404
        if not hmac.compare_digest(str(dados.get('cv') or ''), _versao_credencial(cliente.senha_hash)):
            return jsonify({'erro': 'Sessão expirada. Faça login novamente.'}), 401
        if not _csrf_valido(dados, origem):
            return jsonify({'erro': 'Requisição de segurança inválida. Atualize a página e tente novamente.'}), 403
        request.cliente = cliente
        request.auth_dados = dados
        return f(*args, **kwargs)
    return wrapper


def _base_url_publica():
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL
    if IS_PRODUCTION:
        return ''
    return request.host_url.rstrip('/')


def _smtp_configurado():
    return bool(SMTP_HOST and SMTP_PORT and SMTP_FROM)


def _enviar_mensagem_smtp(mensagem):
    if not _smtp_configurado():
        return False
    contexto_ssl = ssl.create_default_context()
    if SMTP_SECURITY == 'ssl':
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15, context=contexto_ssl) as servidor:
            if SMTP_USER:
                servidor.login(SMTP_USER, SMTP_PASSWORD)
            servidor.send_message(mensagem)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as servidor:
            servidor.ehlo()
            if SMTP_SECURITY == 'tls':
                servidor.starttls(context=contexto_ssl)
                servidor.ehlo()
            if SMTP_USER:
                servidor.login(SMTP_USER, SMTP_PASSWORD)
            servidor.send_message(mensagem)
    return True


def enviar_email_redefinicao_escritorio(destinatario, link_absoluto):
    """Envia o link de redefinição. Retorna True quando o SMTP aceitou a mensagem."""
    mensagem = EmailMessage()
    mensagem['Subject'] = 'ADVOGO SEGURO — redefinição de senha'
    mensagem['From'] = SMTP_FROM
    mensagem['To'] = destinatario
    mensagem.set_content(
        'Recebemos uma solicitação para redefinir a senha do seu escritório no ADVOGO SEGURO.\n\n'
        f'Acesse o link abaixo. Ele expira em {RESET_TOKEN_TTL_MINUTOS} minutos:\n{link_absoluto}\n\n'
        'Se você não solicitou a redefinição, ignore esta mensagem.'
    )
    return _enviar_mensagem_smtp(mensagem)


def enviar_email_confirmacao_escritorio(destinatario, codigo):
    mensagem = EmailMessage()
    mensagem['Subject'] = 'ADVOGO SEGURO — confirme seu e-mail'
    mensagem['From'] = SMTP_FROM
    mensagem['To'] = destinatario
    mensagem.set_content(
        'Confirme o cadastro do seu escritório no ADVOGO SEGURO.\n\n'
        f'Código de confirmação: {codigo}\n\n'
        f'O código expira em {EMAIL_CONFIRMATION_TTL_MINUTES} minutos. '
        'Depois da confirmação, conclua a contratação para iniciar o teste gratuito por 2 dias.\n\n'
        'Se você não realizou este cadastro, ignore esta mensagem.'
    )
    return _enviar_mensagem_smtp(mensagem)


@app.route('/api/logout', methods=['POST'])
def logout_api():
    token, origem = _token_da_requisicao()
    dados = decodificar_token(token) if token else None
    if origem == 'cookie' and dados and not _csrf_valido(dados, origem):
        return jsonify({'erro': 'Requisição de segurança inválida.'}), 403
    resposta = jsonify({'ok': True})
    return _limpar_cookies_sessao(resposta)


@app.route('/api/escritorio/senha', methods=['POST'])
@login_escritorio_obrigatorio
def trocar_senha_escritorio():
    data = request.get_json() or {}
    senha_atual = data.get('senha_atual') or ''
    nova_senha = data.get('nova_senha') or ''

    if not verificar_senha(request.escritorio.senha_hash, senha_atual):
        return jsonify({'erro': 'Senha atual incorreta'}), 401
    if len(nova_senha) < SENHA_MIN_CARACTERES:
        return jsonify({'erro': f'A nova senha deve ter no mínimo {SENHA_MIN_CARACTERES} caracteres'}), 400

    request.escritorio.senha_hash = hash_senha(nova_senha)
    db.session.commit()
    return jsonify({'ok': True, 'mensagem': 'Senha alterada com sucesso'})


@app.route('/api/escritorio/esqueci-senha', methods=['POST'])
def esqueci_senha_escritorio():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    permitido, espera = verificar_limite_acao(f'reset-escritorio:{email or "vazio"}', 5, 900)
    if not permitido:
        return jsonify({'erro': f'Muitas solicitações. Tente novamente em {espera} segundos.'}), 429

    # Se o serviço de e-mail não estiver configurado, a indisponibilidade é
    # igual para qualquer endereço e não revela se uma conta existe.
    if IS_PRODUCTION and not _smtp_configurado():
        app.logger.error('Recuperação de senha indisponível: SMTP não configurado em produção.')
        return jsonify({
            'erro': 'A recuperação de senha por e-mail está temporariamente indisponível. '
                    'Entre em contato com o suporte SPYNET.'
        }), 503
    if IS_PRODUCTION and not PUBLIC_BASE_URL:
        app.logger.error('Recuperação de senha indisponível: PUBLIC_BASE_URL não configurada em produção.')
        return jsonify({
            'erro': 'A recuperação de senha por e-mail está temporariamente indisponível. '
                    'Entre em contato com o suporte SPYNET.'
        }), 503

    escritorio = Escritorio.query.filter_by(email=email).first()

    # Resposta genérica: não revela se o e-mail existe.
    resposta = {
        'ok': True,
        'mensagem': 'Se o e-mail existir em nossa base, um link de redefinição será enviado.'
    }

    if escritorio:
        token_bruto, token_hash = gerar_token_reset()
        escritorio.reset_token = token_hash
        escritorio.reset_token_expira = agora_utc() + timedelta(minutes=RESET_TOKEN_TTL_MINUTOS)
        db.session.commit()

        caminho = f'/redefinir-senha?tipo=escritorio&token={token_bruto}'
        base_publica = _base_url_publica()
        if IS_PRODUCTION and not base_publica:
            app.logger.error('PUBLIC_BASE_URL não configurada em produção; reset por e-mail bloqueado.')
            return jsonify({'erro': 'A recuperação de senha está temporariamente indisponível. Entre em contato com o suporte SPYNET.'}), 503
        link_absoluto = f'{base_publica}{caminho}'

        enviado = False
        try:
            enviado = enviar_email_redefinicao_escritorio(escritorio.email, link_absoluto)
        except Exception as erro:
            app.logger.exception('Falha ao enviar e-mail de redefinição para escritório %s: %s', escritorio.id, erro)

        # Ajuda apenas no desenvolvimento local. Nunca expõe o token em produção.
        if not IS_PRODUCTION and not enviado:
            resposta['link_dev'] = caminho

    return jsonify(resposta)


@app.route('/api/escritorio/redefinir-senha', methods=['POST'])
def redefinir_senha_escritorio():
    data = request.get_json() or {}
    token = data.get('token', '')
    nova_senha = data.get('nova_senha') or ''

    escritorio = Escritorio.query.filter_by(reset_token=hash_token_reset(token)).first()
    if not escritorio or not escritorio.reset_token_expira or escritorio.reset_token_expira < agora_utc():
        return jsonify({'erro': 'Link de redefinição inválido ou expirado. Solicite um novo.'}), 400
    if len(nova_senha) < SENHA_MIN_CARACTERES:
        return jsonify({'erro': f'A nova senha deve ter no mínimo {SENHA_MIN_CARACTERES} caracteres'}), 400

    escritorio.senha_hash = hash_senha(nova_senha)
    escritorio.reset_token = None
    escritorio.reset_token_expira = None
    db.session.commit()
    return jsonify({'ok': True, 'mensagem': 'Senha redefinida com sucesso. Faça login com a nova senha.'})


@app.route('/api/cliente/senha', methods=['POST'])
@login_cliente_obrigatorio
def trocar_senha_cliente():
    data = request.get_json() or {}
    senha_atual = data.get('senha_atual') or ''
    nova_senha = data.get('nova_senha') or ''

    if not verificar_senha(request.cliente.senha_hash, senha_atual):
        return jsonify({'erro': 'Senha atual incorreta'}), 401
    if len(nova_senha) < SENHA_MIN_CARACTERES:
        return jsonify({'erro': f'A nova senha deve ter no mínimo {SENHA_MIN_CARACTERES} caracteres'}), 400

    request.cliente.senha_hash = hash_senha(nova_senha)
    db.session.commit()
    return jsonify({'ok': True, 'mensagem': 'Senha alterada com sucesso'})


@app.route('/api/cliente/esqueci-senha', methods=['POST'])
def esqueci_senha_cliente():
    """
    Como o cliente não usa e-mail para login, o reset gera um token que o
    PRÓPRIO ESCRITÓRIO consegue ver na tela de Processos (vinculado ao cliente)
    e reenviar manualmente por WhatsApp. Integração automática via Z-API pode
    ser plugada depois em envio_whatsapp_reset().
    """
    data = request.get_json() or {}
    telefone = ''.join(filter(str.isdigit, (data.get('telefone') or ''))) 
    permitido, espera = verificar_limite_acao(f'reset-cliente:{telefone or "vazio"}', 5, 900)
    if not permitido:
        return jsonify({'erro': f'Muitas solicitações. Tente novamente em {espera} segundos.'}), 429

    cliente = Cliente.query.filter_by(telefone=telefone).first()
    resposta = {'ok': True, 'mensagem': 'Se o telefone existir em nossa base, solicite ao escritório responsável um novo link de acesso.'}
    # O link só é gerado por um escritório autenticado. Não criamos aqui um
    # token secreto que ninguém consegue entregar ao titular.
    return jsonify(resposta)


@app.route('/api/cliente/redefinir-senha', methods=['POST'])
def redefinir_senha_cliente():
    data = request.get_json() or {}
    token = data.get('token', '')
    nova_senha = data.get('nova_senha') or ''

    cliente = Cliente.query.filter_by(reset_token=hash_token_reset(token)).first()
    if not cliente or not cliente.reset_token_expira or cliente.reset_token_expira < agora_utc():
        return jsonify({'erro': 'Link de redefinição inválido ou expirado. Solicite um novo ao seu escritório.'}), 400
    if len(nova_senha) < SENHA_MIN_CARACTERES:
        return jsonify({'erro': f'A nova senha deve ter no mínimo {SENHA_MIN_CARACTERES} caracteres'}), 400

    cliente.senha_hash = hash_senha(nova_senha)
    cliente.reset_token = None
    cliente.reset_token_expira = None
    db.session.commit()
    return jsonify({'ok': True, 'mensagem': 'Senha redefinida com sucesso. Faça login com a nova senha.'})


@app.route('/api/escritorio/cliente/<int:cliente_id>/link-reset', methods=['POST'])
@login_escritorio_obrigatorio
def gerar_link_reset_cliente(cliente_id):
    """Permite ao escritório gerar/copiar um link de redefinição para reenviar ao cliente por WhatsApp."""
    processo = Processo.query.filter_by(cliente_id=cliente_id, escritorio_id=request.escritorio.id).first()
    if not processo:
        return jsonify({'erro': 'Cliente não encontrado neste escritório'}), 404

    cliente = processo.cliente
    if _cliente_possui_processos_de_outro_escritorio(cliente.id, request.escritorio.id):
        return jsonify({
            'erro': 'Este cliente está vinculado a mais de um escritório. Por segurança, a redefinição de senha deve ser tratada pelo suporte.'
        }), 409

    token_bruto, token_hash = gerar_token_reset()
    cliente.reset_token = token_hash
    cliente.reset_token_expira = agora_utc() + timedelta(minutes=RESET_TOKEN_TTL_MINUTOS)
    db.session.commit()

    return jsonify({'link': f"/redefinir-senha?tipo=cliente&token={token_bruto}", 'cliente_nome': cliente.nome})


# ──────────────────────────────────────────────
# ROTAS — ESCRITÓRIO (B2B)
# ──────────────────────────────────────────────

def _somente_digitos(valor):
    return re.sub(r'\D', '', str(valor or ''))


def _hash_codigo_confirmacao(codigo):
    return hashlib.sha256(str(codigo).encode('utf-8')).hexdigest()


def _gerar_codigo_confirmacao():
    return f'{secrets.randbelow(1_000_000):06d}'


def _cnpj_ja_cadastrado(cnpj_normalizado):
    if not cnpj_normalizado:
        return False
    for escritorio in Escritorio.query.filter(Escritorio.cnpj.isnot(None)).all():
        if _somente_digitos(escritorio.cnpj) == cnpj_normalizado:
            if (
                not escritorio.email_confirmacao_obrigatoria
                or escritorio.email_confirmado_em
                or escritorio.trial_utilizado_em
                or normalizar_codigo_plano(escritorio.plano) != 'trial'
            ):
                return True
    return False


def _cpf_ja_cadastrado(cpf_normalizado):
    if not cpf_normalizado:
        return False

    for escritorio in Escritorio.query.filter(Escritorio.cpf.isnot(None)).all():
        if _somente_digitos(escritorio.cpf) == cpf_normalizado:
            if (
                not escritorio.email_confirmacao_obrigatoria
                or escritorio.email_confirmado_em
                or escritorio.trial_utilizado_em
                or normalizar_codigo_plano(escritorio.plano) != 'trial'
            ):
                return True
    return False


def _outro_escritorio_ja_usou_beneficio_documento(
    tipo_pessoa, documento_normalizado, escritorio_id
):
    if not documento_normalizado:
        return False

    campo_documento = 'cpf' if tipo_pessoa == 'pf' else 'cnpj'

    for escritorio in Escritorio.query.filter(Escritorio.id != escritorio_id).all():
        documento_escritorio = _somente_digitos(
            getattr(escritorio, campo_documento, None)
        )
        if documento_escritorio != documento_normalizado:
            continue

        if (
            escritorio.trial_utilizado_em
            or escritorio.assinatura_status in {'trialing', 'active'}
            or (
                normalizar_codigo_plano(escritorio.plano) != 'trial'
                and escritorio.plano_ativo()
            )
        ):
            return True

    return False


def _outro_escritorio_ja_usou_beneficio(cnpj_normalizado, escritorio_id):
    # Compatibilidade com chamadas existentes baseadas em CNPJ.
    return _outro_escritorio_ja_usou_beneficio_documento(
        'pj', cnpj_normalizado, escritorio_id
    )


def _registrar_escritorio_comercial(data):
    nome = (data.get('nome') or '').strip()
    email = (data.get('email') or '').strip().lower()
    senha = data.get('senha') or ''
    tipo_pessoa = str(data.get('tipo_pessoa') or 'pj').strip().lower()
    cpf = _somente_digitos(data.get('cpf'))
    oab = (data.get('oab') or '').strip().upper()
    cnpj = _somente_digitos(data.get('cnpj'))
    plano = normalizar_codigo_plano(data.get('plano'))

    permitido, espera = verificar_limite_acao(
        f'registro-comercial:{request.remote_addr or "desconhecido"}',
        max_tentativas=5,
        janela_segundos=3600,
    )
    if not permitido:
        return jsonify({'erro': f'Muitos cadastros. Tente novamente em {espera} segundos.'}), 429

    if not nome or not email or len(senha) < SENHA_MIN_CARACTERES:
        return jsonify({
            'erro': f'Preencha nome, e-mail e senha (mín. {SENHA_MIN_CARACTERES} caracteres).'
        }), 400
    if tipo_pessoa not in {'pf', 'pj'}:
        return jsonify({'erro': 'Selecione advogado individual ou escritório.'}), 400

    if tipo_pessoa == 'pf':
        if len(cpf) != 11:
            return jsonify({'erro': 'Informe um CPF com 11 dígitos.'}), 400
        if not oab or len(oab) > 30:
            return jsonify({'erro': 'Informe a OAB do advogado.'}), 400
        cnpj = None
    else:
        if len(cnpj) != 14:
            return jsonify({'erro': 'Informe um CNPJ com 14 dígitos.'}), 400
        cpf = None
        oab = None

    if plano not in {'profissional', 'escritorio', 'blindagem'}:
        return jsonify({'erro': 'Escolha um plano disponível para contratação online.'}), 400
    if Escritorio.query.filter_by(email=email).first():
        return jsonify({'erro': 'E-mail já cadastrado.'}), 409
    if tipo_pessoa == 'pf':
        if _cpf_ja_cadastrado(cpf):
            return jsonify({'erro': 'Este CPF já possui cadastro no ADVOGO SEGURO.'}), 409
    elif _cnpj_ja_cadastrado(cnpj):
        return jsonify({'erro': 'Este CNPJ já possui cadastro no ADVOGO SEGURO.'}), 409

    codigo = _gerar_codigo_confirmacao()
    escritorio = Escritorio(
        nome=nome,
        email=email,
        tipo_pessoa=tipo_pessoa,
        cpf=cpf,
        oab=oab,
        cnpj=cnpj,
        senha_hash=hash_senha(senha),
        plano='trial',
        plano_expira=agora_utc(),
        plano_pretendido=plano,
        assinatura_status='aguardando_email',
        email_confirmacao_obrigatoria=True,
        email_confirmacao_token_hash=_hash_codigo_confirmacao(codigo),
        email_confirmacao_expira=(
            agora_utc() + timedelta(minutes=EMAIL_CONFIRMATION_TTL_MINUTES)
        ),
    )
    db.session.add(escritorio)
    db.session.commit()

    email_enviado = False
    try:
        email_enviado = enviar_email_confirmacao_escritorio(email, codigo)
    except (OSError, smtplib.SMTPException):
        app.logger.exception('Falha ao enviar confirmação para escritorio_id=%s.', escritorio.id)

    resposta = {
        'ok': True,
        'email': email,
        'plano': plano,
        'confirmacao_email': True,
        'email_enviado': email_enviado,
        'mensagem': (
            'Enviamos um código de confirmação para o seu e-mail.'
            if email_enviado else
            'Cadastro criado. O envio do código está temporariamente indisponível; tente reenviar.'
        ),
    }
    if not IS_PRODUCTION:
        resposta['codigo_dev'] = codigo
    return jsonify(resposta), 201


@app.route('/api/comercial/registro', methods=['POST'])
def registro_escritorio_comercial():
    return _registrar_escritorio_comercial(request.get_json(silent=True) or {})


@app.route('/api/comercial/confirmar-email', methods=['POST'])
def confirmar_email_comercial():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    codigo = _somente_digitos(data.get('codigo'))

    permitido, espera = verificar_limite_acao(
        f'confirmar-email:{email}', max_tentativas=8, janela_segundos=900
    )
    if not permitido:
        return jsonify({'erro': f'Muitas tentativas. Tente novamente em {espera} segundos.'}), 429
    if not email or len(codigo) != 6:
        return jsonify({'erro': 'Informe o e-mail e o código de 6 dígitos.'}), 400

    escritorio = Escritorio.query.filter_by(email=email).first()
    if not escritorio or not escritorio.email_confirmacao_obrigatoria:
        return jsonify({'erro': 'Não foi possível confirmar este cadastro.'}), 400
    if escritorio.email_confirmado_em:
        return _resposta_com_sessao({
            'ok': True,
            'nome': escritorio.nome,
            'plano': escritorio.plano,
            'plano_pretendido': escritorio.plano_pretendido,
            'proximo': '/contratacao',
        }, {'id': escritorio.id, 'tipo': 'escritorio'}, escritorio.senha_hash)
    if not escritorio.email_confirmacao_expira or escritorio.email_confirmacao_expira <= agora_utc():
        return jsonify({'erro': 'O código expirou. Solicite um novo código.'}), 400
    if not escritorio.email_confirmacao_token_hash or not hmac.compare_digest(
        escritorio.email_confirmacao_token_hash,
        _hash_codigo_confirmacao(codigo),
    ):
        return jsonify({'erro': 'Código de confirmação inválido.'}), 400

    escritorio.email_confirmado_em = agora_utc()
    escritorio.email_confirmacao_token_hash = None
    escritorio.email_confirmacao_expira = None
    escritorio.assinatura_status = 'aguardando_pagamento'
    db.session.commit()
    limpar_tentativas(f'confirmar-email:{email}')

    return _resposta_com_sessao({
        'ok': True,
        'nome': escritorio.nome,
        'plano': escritorio.plano,
        'plano_pretendido': escritorio.plano_pretendido,
        'proximo': '/contratacao',
    }, {'id': escritorio.id, 'tipo': 'escritorio'}, escritorio.senha_hash)


@app.route('/api/comercial/reenviar-confirmacao', methods=['POST'])
def reenviar_confirmacao_comercial():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    permitido, espera = verificar_limite_acao(
        f'reenviar-confirmacao:{email}', max_tentativas=3, janela_segundos=3600
    )
    if not permitido:
        return jsonify({'erro': f'Aguarde {espera} segundos antes de reenviar.'}), 429

    escritorio = Escritorio.query.filter_by(email=email).first()
    resposta_padrao = {
        'ok': True,
        'mensagem': 'Se o cadastro estiver pendente, um novo código será enviado.',
    }
    if not escritorio or escritorio.email_confirmado():
        return jsonify(resposta_padrao)

    codigo = _gerar_codigo_confirmacao()
    escritorio.email_confirmacao_token_hash = _hash_codigo_confirmacao(codigo)
    escritorio.email_confirmacao_expira = (
        agora_utc() + timedelta(minutes=EMAIL_CONFIRMATION_TTL_MINUTES)
    )
    db.session.commit()

    try:
        email_enviado = enviar_email_confirmacao_escritorio(email, codigo)
    except (OSError, smtplib.SMTPException):
        email_enviado = False
        app.logger.exception('Falha ao reenviar confirmação para escritorio_id=%s.', escritorio.id)
    resposta_padrao['email_enviado'] = email_enviado
    if not IS_PRODUCTION:
        resposta_padrao['codigo_dev'] = codigo
    return jsonify(resposta_padrao)

@app.route('/api/escritorio/registro', methods=['POST'])
def registro_escritorio():
    data = request.get_json() or {}
    if COMMERCIAL_FLOW_ENABLED:
        return _registrar_escritorio_comercial(data)
    nome = (data.get('nome') or '').strip()
    email = (data.get('email') or '').strip().lower()
    senha = data.get('senha') or ''
    cnpj = (data.get('cnpj') or '').strip()

    if not nome or not email or len(senha) < SENHA_MIN_CARACTERES:
        return jsonify({'erro': f'Preencha nome, email e senha (mín. {SENHA_MIN_CARACTERES} caracteres)'}), 400

    if Escritorio.query.filter_by(email=email).first():
        return jsonify({'erro': 'Email já cadastrado'}), 409

    escritorio = Escritorio(
        nome=nome, email=email, cnpj=cnpj,
        senha_hash=hash_senha(senha),
        plano='trial',
        plano_expira=agora_utc()
    )
    db.session.add(escritorio)
    db.session.commit()

    return _resposta_com_sessao({
        'nome': escritorio.nome,
        'plano': escritorio.plano, 'plano_ativo': escritorio.plano_ativo()
    }, {'id': escritorio.id, 'tipo': 'escritorio'}, escritorio.senha_hash)


@app.route('/api/escritorio/login', methods=['POST'])
def login_escritorio():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    senha = data.get('senha') or ''

    permitido, espera = verificar_rate_limit(email)
    if not permitido:
        return jsonify({'erro': f'Muitas tentativas de login. Tente novamente em {espera} segundos.'}), 429

    escritorio = Escritorio.query.filter_by(email=email).first()
    if not escritorio or not verificar_senha(escritorio.senha_hash, senha):
        registrar_tentativa_falha(email)
        return jsonify({'erro': 'Email ou senha incorretos'}), 401

    if not escritorio.email_confirmado():
        return jsonify({
            'erro': 'Confirme seu e-mail para continuar.',
            'confirmacao_email': True,
            'email': escritorio.email,
        }), 403

    limpar_tentativas(email)
    # upgrade silencioso de hash legado (sha256) para PBKDF2
    if len(escritorio.senha_hash) == 64 and ':' not in escritorio.senha_hash:
        escritorio.senha_hash = hash_senha(senha)
        db.session.commit()

    return _resposta_com_sessao({
        'nome': escritorio.nome,
        'plano': escritorio.plano, 'plano_ativo': escritorio.plano_ativo()
    }, {'id': escritorio.id, 'tipo': 'escritorio'}, escritorio.senha_hash)


@app.route('/api/escritorio/plano', methods=['GET'])
@login_escritorio_obrigatorio
def dados_plano_escritorio():
    codigo, config = request.escritorio.config_plano()
    ativos = Advogado.query.filter_by(
        escritorio_id=request.escritorio.id,
        ativo=True
    ).count()
    limite = config['limite_advogados']
    restante = None if limite is None else max(limite - ativos, 0)
    plano_ativo = request.escritorio.plano_ativo()
    pode_adicionar = plano_ativo and (limite is None or ativos < limite)
    horas_teste_restantes = None
    if codigo == 'trial' and request.escritorio.plano_expira:
        segundos = max((request.escritorio.plano_expira - agora_utc()).total_seconds(), 0)
        horas_teste_restantes = int((segundos + 3599) // 3600)

    if not plano_ativo:
        mensagem_limite = 'Seu plano está inativo. Regularize o acesso para continuar.'
    elif limite is not None and ativos >= limite:
        mensagem_limite = (
            f'Seu plano {config["nome"]} permite até {limite} advogado(s) ativo(s). '
            'Para adicionar outro profissional, altere o plano.'
        )
    else:
        mensagem_limite = None

    return jsonify({
        'codigo': codigo,
        'codigo_salvo': request.escritorio.plano,
        'nome': config['nome'],
        'preco_mensal': config['preco_mensal'],
        'implantacao': config['implantacao'],
        'limite_advogados': limite,
        'advogados_ativos': ativos,
        'advogados_restantes': restante,
        'plano_ativo': plano_ativo,
        'assinatura_status': request.escritorio.assinatura_status,
        'plano_pretendido': request.escritorio.plano_pretendido,
        'trial_dias': TRIAL_DIAS,
        'horas_teste_restantes': horas_teste_restantes,
        'pode_adicionar_advogado': pode_adicionar,
        'mensagem_limite': mensagem_limite,
        'expira_em': (
            request.escritorio.plano_expira.isoformat()
            if request.escritorio.plano_expira else None
        ),
    })


@app.route('/api/escritorio/advogados', methods=['GET', 'POST'])
@login_escritorio_obrigatorio
def advogados():
    if request.method == 'POST':
        if not request.escritorio.plano_ativo():
            return jsonify({
                'erro': 'Plano inativo. Regularize o acesso para cadastrar advogados.',
                'limite_plano': True
            }), 403

        codigo_plano, config_plano = request.escritorio.config_plano()
        limite = config_plano['limite_advogados']
        ativos = Advogado.query.filter_by(
            escritorio_id=request.escritorio.id,
            ativo=True
        ).count()

        if limite is not None and ativos >= limite:
            return jsonify({
                'erro': (
                    f'Seu plano {config_plano["nome"]} permite até {limite} '
                    'advogado(s) ativo(s). Para adicionar outro profissional, '
                    'acesse a página de planos.'
                ),
                'limite_plano': True,
                'plano': codigo_plano,
                'limite_advogados': limite,
                'advogados_ativos': ativos,
            }), 403

        data = request.get_json() or {}
        nome = (data.get('nome') or '').strip()
        telefone = (data.get('telefone_oficial') or '').strip()
        if not nome or not telefone:
            return jsonify({'erro': 'Informe o nome e o telefone oficial do advogado.'}), 400

        foto_url = (data.get('foto_url') or '').strip()
        if not _url_foto_permitida(foto_url):
            return jsonify({'erro': 'URL de foto inválida. Use HTTPS ou envie a imagem pelo sistema.'}), 400
        adv = Advogado(
            escritorio_id=request.escritorio.id,
            nome=nome,
            oab=(data.get('oab') or '').strip(),
            telefone_oficial=telefone,
            foto_url=foto_url
        )
        db.session.add(adv)
        db.session.commit()
        return jsonify({'id': adv.id, 'nome': adv.nome})

    lista = Advogado.query.filter_by(escritorio_id=request.escritorio.id).all()
    return jsonify([{
        'id': a.id, 'nome': a.nome, 'oab': a.oab,
        'telefone_oficial': a.telefone_oficial, 'foto_url': _url_foto_banco(a),
        'ativo': a.ativo
    } for a in lista])


@app.route('/api/escritorio/advogados/<int:advogado_id>', methods=['PUT', 'DELETE'])
@login_escritorio_obrigatorio
def advogado_detalhe(advogado_id):
    adv = Advogado.query.filter_by(id=advogado_id, escritorio_id=request.escritorio.id).first()
    if not adv:
        return jsonify({'erro': 'Advogado não encontrado'}), 404

    if request.method == 'DELETE':
        data = request.get_json(silent=True) or {}
        if (data.get('confirmacao') or '').strip().upper() != 'EXCLUIR':
            return jsonify({'erro': 'Para excluir definitivamente, confirme digitando EXCLUIR.'}), 400
        try:
            _excluir_advogado_em_cascata(adv, request.escritorio.id)
            db.session.commit()
        except SQLAlchemyError as erro:
            db.session.rollback()
            app.logger.exception('Falha ao excluir advogado %s: %s', advogado_id, erro)
            return jsonify({'erro': 'Não foi possível excluir o advogado. Nenhuma alteração foi salva.'}), 500
        return jsonify({'ok': True})

    data = request.get_json() or {}
    if 'nome' in data:
        if not isinstance(data['nome'], str) or not data['nome'].strip():
            return jsonify({'erro': 'Nome do advogado inválido.'}), 400
        adv.nome = data['nome'].strip()
    if 'oab' in data:
        if data['oab'] is not None and not isinstance(data['oab'], str):
            return jsonify({'erro': 'OAB inválida.'}), 400
        adv.oab = (data['oab'] or '').strip()
    if 'telefone_oficial' in data:
        if not isinstance(data['telefone_oficial'], str) or not data['telefone_oficial'].strip():
            return jsonify({'erro': 'Telefone oficial inválido.'}), 400
        adv.telefone_oficial = data['telefone_oficial'].strip()
    if 'foto_url' in data:
        if data['foto_url'] is not None and not isinstance(data['foto_url'], str):
            return jsonify({'erro': 'URL da foto inválida.'}), 400
        foto_url = (data['foto_url'] or '').strip()
        foto_interna_atual = _url_foto_banco(adv) if adv.foto_blob and adv.foto_token else None
        if foto_interna_atual and foto_url == foto_interna_atual:
            pass  # edição normal do cadastro não apaga a foto persistida
        else:
            if not _url_foto_permitida(foto_url):
                return jsonify({'erro': 'URL de foto inválida. Use HTTPS ou envie a imagem pelo sistema.'}), 400
            adv.foto_url = foto_url
            _limpar_foto_banco(adv)
    db.session.commit()
    return jsonify({'id': adv.id, 'nome': adv.nome})


@app.route('/api/escritorio/advogados/<int:advogado_id>/resumo-exclusao', methods=['GET'])
@login_escritorio_obrigatorio
def resumo_exclusao_advogado(advogado_id):
    adv = Advogado.query.filter_by(id=advogado_id, escritorio_id=request.escritorio.id).first()
    if not adv:
        return jsonify({'erro': 'Advogado não encontrado'}), 404

    processos_ids = [p.id for p in Processo.query.filter_by(advogado_id=adv.id, escritorio_id=request.escritorio.id).all()]
    return jsonify({
        'processos': len(processos_ids),
        'tentativas_suspeitas': TentativaContato.query.filter(TentativaContato.processo_id.in_(processos_ids)).count() if processos_ids else 0,
        'contatos_seguros': ContatoSeguro.query.filter_by(advogado_id=adv.id).count(),
    })


@app.route('/api/escritorio/advogados/<int:advogado_id>/desativar', methods=['POST'])
@login_escritorio_obrigatorio
def desativar_advogado(advogado_id):
    adv = Advogado.query.filter_by(id=advogado_id, escritorio_id=request.escritorio.id).first()
    if not adv:
        return jsonify({'erro': 'Advogado não encontrado'}), 404
    adv.ativo = False
    db.session.commit()
    return jsonify({'ok': True, 'ativo': adv.ativo})


@app.route('/api/escritorio/advogados/<int:advogado_id>/reativar', methods=['POST'])
@login_escritorio_obrigatorio
def reativar_advogado(advogado_id):
    adv = Advogado.query.filter_by(id=advogado_id, escritorio_id=request.escritorio.id).first()
    if not adv:
        return jsonify({'erro': 'Advogado não encontrado'}), 404
    if adv.ativo:
        return jsonify({'ok': True, 'ativo': True})
    if not request.escritorio.plano_ativo():
        return jsonify({'erro': 'Plano inativo. Regularize o acesso para reativar advogados.'}), 403

    _, config_plano = request.escritorio.config_plano()
    limite = config_plano['limite_advogados']
    ativos = Advogado.query.filter_by(
        escritorio_id=request.escritorio.id,
        ativo=True
    ).count()
    if limite is not None and ativos >= limite:
        return jsonify({
            'erro': (
                f'Seu plano {config_plano["nome"]} permite até {limite} '
                'advogado(s) ativo(s). Altere o plano antes de reativar.'
            ),
            'limite_plano': True
        }), 403

    adv.ativo = True
    db.session.commit()
    return jsonify({'ok': True, 'ativo': adv.ativo})


def _extensao_permitida(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in UPLOAD_EXTENSOES_PERMITIDAS


def _conteudo_imagem_compativel(arquivo, extensao):
    """Valida assinatura binária básica; não confia só no nome/extensão."""
    cabecalho = arquivo.stream.read(16)
    arquivo.stream.seek(0)
    if extensao in ('jpg', 'jpeg'):
        return cabecalho.startswith(b'\xff\xd8\xff')
    if extensao == 'png':
        return cabecalho.startswith(b'\x89PNG\r\n\x1a\n')
    if extensao == 'webp':
        return len(cabecalho) >= 12 and cabecalho[:4] == b'RIFF' and cabecalho[8:12] == b'WEBP'
    return False


def _url_foto_permitida(url):
    url = (url or '').strip()
    if not url:
        return True
    return url.startswith('/static/uploads/advogados/') or url.startswith('https://')


def _mime_foto_por_extensao(extensao):
    extensao = (extensao or '').lower()
    return {
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'webp': 'image/webp',
    }.get(extensao)


def _url_foto_banco(advogado):
    if advogado and advogado.foto_token and advogado.foto_blob:
        return f'/api/publico/foto-advogado/{advogado.foto_token}'
    return advogado.foto_url if advogado else None


def _limpar_foto_banco(advogado):
    advogado.foto_blob = None
    advogado.foto_mime = None
    advogado.foto_token = None


def _migrar_fotos_legadas_local_para_banco():
    """Migra fotos locais legadas quando o arquivo ainda existe no host.

    É melhor-esforço e nunca impede o startup: um deploy novo pode não receber
    arquivos antigos de um filesystem efêmero. Nesse caso, o usuário apenas
    precisará reenviar a foto uma vez pela interface.
    """
    inspetor = inspect(db.engine)
    if not inspetor.has_table('advogados'):
        return 0
    colunas = {c['name'] for c in inspetor.get_columns('advogados')}
    if not {'foto_blob', 'foto_mime', 'foto_token'}.issubset(colunas):
        return 0

    migradas = 0
    candidatos = Advogado.query.filter(
        Advogado.foto_blob.is_(None),
        Advogado.foto_url.like('/static/uploads/advogados/%')
    ).all()
    for adv in candidatos:
        caminho = os.path.join(app.root_path, adv.foto_url.lstrip('/'))
        if not os.path.isfile(caminho):
            continue
        try:
            tamanho = os.path.getsize(caminho)
            if tamanho <= 0 or tamanho > UPLOAD_TAMANHO_MAXIMO_BYTES:
                continue
            extensao = caminho.rsplit('.', 1)[-1].lower() if '.' in caminho else ''
            mime = _mime_foto_por_extensao(extensao)
            if not mime:
                continue
            with open(caminho, 'rb') as f:
                dados = f.read()
            # Reutiliza a mesma validação de assinatura usada no upload.
            class _ArquivoMemoria:
                def __init__(self, conteudo):
                    self.stream = io_module.BytesIO(conteudo)
            if not _conteudo_imagem_compativel(_ArquivoMemoria(dados), extensao):
                continue
            adv.foto_blob = dados
            adv.foto_mime = mime
            adv.foto_token = secrets.token_urlsafe(24)
            adv.foto_url = _url_foto_banco(adv)
            migradas += 1
        except OSError:
            app.logger.warning('Não foi possível migrar foto legada do advogado id=%s.', adv.id)
    if migradas:
        db.session.commit()
        app.logger.info('[MIGRACAO] %s foto(s) legada(s) persistida(s) no banco.', migradas)
    return migradas


@app.route('/api/publico/foto-advogado/<token>', methods=['GET'])
def foto_advogado_publica(token):
    """Entrega a foto persistida no banco por token aleatório não enumerável."""
    adv = Advogado.query.filter_by(foto_token=token).first()
    if not adv or not adv.foto_blob or not adv.foto_mime:
        return jsonify({'erro': 'Foto não encontrada.'}), 404
    resposta = Response(bytes(adv.foto_blob), mimetype=adv.foto_mime)
    resposta.headers['Content-Length'] = str(len(adv.foto_blob))
    return resposta


@app.route('/api/escritorio/advogados/<int:advogado_id>/foto', methods=['POST'])
@login_escritorio_obrigatorio
def upload_foto_advogado(advogado_id):
    """Persiste a foto do advogado no banco; não depende do disco local da aplicação."""
    adv = Advogado.query.filter_by(id=advogado_id, escritorio_id=request.escritorio.id).first()
    if not adv:
        return jsonify({'erro': 'Advogado não encontrado'}), 404

    arquivo = request.files.get('foto')
    if not arquivo or arquivo.filename == '':
        return jsonify({'erro': 'Nenhum arquivo enviado.'}), 400
    if not _extensao_permitida(arquivo.filename):
        return jsonify({'erro': 'Formato não permitido. Use jpg, jpeg, png ou webp.'}), 400

    extensao = arquivo.filename.rsplit('.', 1)[1].lower()
    if not _conteudo_imagem_compativel(arquivo, extensao):
        return jsonify({'erro': 'O conteúdo do arquivo não corresponde a uma imagem válida do formato informado.'}), 400

    dados = arquivo.stream.read(UPLOAD_TAMANHO_MAXIMO_BYTES + 1)
    if not dados:
        return jsonify({'erro': 'Arquivo de imagem vazio.'}), 400
    if len(dados) > UPLOAD_TAMANHO_MAXIMO_BYTES:
        return jsonify({'erro': 'Imagem acima do limite permitido.'}), 413

    mime = _mime_foto_por_extensao(extensao)
    if not mime:
        return jsonify({'erro': 'Formato de imagem não suportado.'}), 400

    caminho_antigo = None
    if adv.foto_url and adv.foto_url.startswith('/static/uploads/advogados/'):
        caminho_antigo = os.path.join(app.root_path, adv.foto_url.lstrip('/'))

    adv.foto_blob = dados
    adv.foto_mime = mime
    adv.foto_token = secrets.token_urlsafe(24)
    adv.foto_url = _url_foto_banco(adv)
    db.session.commit()

    # Remove apenas a cópia legada local depois que a persistência no banco foi confirmada.
    if caminho_antigo and os.path.exists(caminho_antigo):
        try:
            os.remove(caminho_antigo)
        except OSError:
            app.logger.warning('Foto antiga persistiu em disco após migração do advogado id=%s.', adv.id)

    return jsonify({'ok': True, 'foto_url': adv.foto_url})


@app.route('/api/escritorio/processos', methods=['GET', 'POST'])
@login_escritorio_obrigatorio
def processos():
    if not request.escritorio.plano_ativo():
        return jsonify({'erro': 'Plano inativo. Assine para continuar.', 'limite': True}), 403

    if request.method == 'POST':
        codigo_plano, _ = request.escritorio.config_plano()
        if codigo_plano == 'trial':
            processos_existentes = Processo.query.filter_by(
                escritorio_id=request.escritorio.id
            ).count()
            if processos_existentes >= 1:
                return jsonify({
                    'erro': 'O teste gratuito permite 1 cliente e 1 processo.',
                    'limite_plano': True,
                }), 403
        data = request.get_json() or {}

        cliente_nome = (data.get('cliente_nome') or '').strip()
        telefone_normalizado = ''.join(filter(str.isdigit, (data.get('cliente_telefone') or ''))) 
        cliente_email = (data.get('cliente_email') or '').strip()

        try:
            advogado_id = int(data.get('advogado_id'))
        except (TypeError, ValueError):
            return jsonify({'erro': 'Selecione um advogado válido.'}), 400

        advogado = Advogado.query.filter_by(
            id=advogado_id,
            escritorio_id=request.escritorio.id,
            ativo=True
        ).first()
        if not advogado:
            return jsonify({'erro': 'Advogado ativo não encontrado neste escritório.'}), 404

        if not cliente_nome:
            return jsonify({'erro': 'Informe o nome do cliente.'}), 400
        if len(telefone_normalizado) < 8:
            return jsonify({'erro': 'Informe um telefone válido para o cliente.'}), 400

        cliente = Cliente.query.filter_by(telefone=telefone_normalizado).first()
        cliente_existente = bool(cliente)
        senha_temp = None
        if not cliente:
            senha_temp = secrets.token_urlsafe(9)
            cliente = Cliente(
                nome=cliente_nome,
                telefone=telefone_normalizado,
                email=cliente_email,
                senha_hash=hash_senha(senha_temp)
            )
            db.session.add(cliente)
            db.session.flush()

        processo = Processo(
            escritorio_id=request.escritorio.id,
            advogado_id=advogado.id,
            cliente_id=cliente.id,
            codigo_unico=gerar_codigo_unico(),
            token_cliente=secrets.token_urlsafe(28),
            numero_processo=(data.get('numero_processo') or '').strip(),
            descricao=(data.get('descricao') or '').strip()
        )
        db.session.add(processo)
        db.session.commit()

        return jsonify({
            'id': processo.id,
            'codigo_unico': processo.codigo_unico,
            'cliente_id': cliente.id,
            'cliente_nome': cliente.nome,
            'cliente_existente': cliente_existente,
            'senha_temporaria': senha_temp,
            'mensagem_acesso': (
                'Cliente já cadastrado. A senha existente continua válida; se necessário, use Reenviar acesso.'
                if cliente_existente else
                'Cliente novo. Entregue a senha temporária uma única vez e oriente a troca após o primeiro acesso.'
            ),
            'link_cliente_seguro': f'/cliente/seguro/{processo.token_cliente}'
        })

    lista = Processo.query.options(
        joinedload(Processo.cliente),
        joinedload(Processo.advogado),
    ).filter_by(escritorio_id=request.escritorio.id).order_by(Processo.criado_em.desc()).all()
    precisa_commit = False
    for p in lista:
        if not p.token_cliente:  # compatibilidade: processos antigos (pré-Sprint 3) ganham token agora
            p.token_cliente = secrets.token_urlsafe(28)
            precisa_commit = True
    if precisa_commit:
        db.session.commit()

    return jsonify([{
        'id': p.id, 'codigo_unico': p.codigo_unico, 'numero_processo': p.numero_processo,
        'descricao': p.descricao, 'status': p.status,
        'cliente_id': p.cliente_id, 'advogado_id': p.advogado_id,
        'cliente_nome': p.cliente.nome, 'cliente_telefone': p.cliente.telefone,
        'advogado_nome': p.advogado.nome if p.advogado else None,
        'criado_em': p.criado_em.strftime('%d/%m/%Y'),
        'link_cliente_seguro': f'/cliente/seguro/{p.token_cliente}'
    } for p in lista])


@app.route('/api/escritorio/processos/<int:processo_id>', methods=['PUT', 'DELETE'])
@login_escritorio_obrigatorio
def processo_detalhe(processo_id):
    processo = Processo.query.filter_by(id=processo_id, escritorio_id=request.escritorio.id).first()
    if not processo:
        return jsonify({'erro': 'Processo não encontrado'}), 404

    if request.method == 'DELETE':
        try:
            _excluir_processo_em_cascata(processo)
            db.session.commit()
        except SQLAlchemyError as erro:
            db.session.rollback()
            app.logger.exception('Falha ao excluir processo %s: %s', processo_id, erro)
            return jsonify({'erro': 'Não foi possível excluir o processo. Nenhuma alteração foi salva.'}), 500
        return jsonify({'ok': True})

    data = request.get_json() or {}
    if 'numero_processo' in data:
        if data['numero_processo'] is not None and not isinstance(data['numero_processo'], str):
            return jsonify({'erro': 'Número do processo inválido.'}), 400
        processo.numero_processo = (data['numero_processo'] or '').strip()
    if 'descricao' in data:
        if data['descricao'] is not None and not isinstance(data['descricao'], str):
            return jsonify({'erro': 'Descrição inválida.'}), 400
        processo.descricao = (data['descricao'] or '').strip()
    if 'advogado_id' in data and data['advogado_id']:
        try:
            novo_advogado_id = int(data['advogado_id'])
        except (TypeError, ValueError):
            return jsonify({'erro': 'Advogado inválido.'}), 400
        novo_advogado = Advogado.query.filter_by(
            id=novo_advogado_id,
            escritorio_id=request.escritorio.id,
            ativo=True
        ).first()
        if not novo_advogado:
            return jsonify({'erro': 'Advogado ativo não encontrado neste escritório.'}), 404
        processo.advogado_id = novo_advogado.id
    if 'status' in data and data['status'] in ('ativo', 'arquivado'):
        processo.status = data['status']
    db.session.commit()
    return jsonify({'id': processo.id, 'ok': True})


@app.route('/api/escritorio/processos/<int:processo_id>/resumo-exclusao', methods=['GET'])
@login_escritorio_obrigatorio
def resumo_exclusao_processo(processo_id):
    """Contagens exibidas no modal de confirmação antes de excluir um processo."""
    processo = Processo.query.filter_by(id=processo_id, escritorio_id=request.escritorio.id).first()
    if not processo:
        return jsonify({'erro': 'Processo não encontrado'}), 404

    return jsonify({
        'tentativas_suspeitas': TentativaContato.query.filter_by(processo_id=processo.id).count(),
        'contatos_seguros': ContatoSeguro.query.filter_by(processo_id=processo.id).count(),
        'acessos_publicos': AcessoPublicoLog.query.filter_by(processo_id=processo.id).count(),
    })


@app.route('/api/escritorio/tentativas', methods=['GET'])
@login_escritorio_obrigatorio
def listar_tentativas():
    tentativas = TentativaContato.query.join(Processo).options(
        joinedload(TentativaContato.processo).joinedload(Processo.cliente)
    ).filter(
        Processo.escritorio_id == request.escritorio.id
    ).order_by(TentativaContato.criado_em.desc()).limit(100).all()

    return jsonify([{
        'id': t.id, 'numero_suspeito': t.numero_suspeito, 'canal': t.canal,
        'descricao': t.descricao, 'confirmado_golpe': t.confirmado_golpe,
        'processo_codigo': t.processo.codigo_unico,
        'cliente_nome': t.processo.cliente.nome,
        'criado_em': t.criado_em.strftime('%d/%m/%Y %H:%M')
    } for t in tentativas])


def _tentativa_pertence_ao_escritorio(tentativa, escritorio_id):
    return tentativa.processo is not None and tentativa.processo.escritorio_id == escritorio_id


@app.route('/api/escritorio/tentativas/<int:tentativa_id>', methods=['DELETE'])
@login_escritorio_obrigatorio
def excluir_tentativa(tentativa_id):
    tentativa = db.session.get(TentativaContato, tentativa_id)
    if not tentativa or not _tentativa_pertence_ao_escritorio(tentativa, request.escritorio.id):
        return jsonify({'erro': 'Tentativa suspeita não encontrada.'}), 404
    try:
        db.session.delete(tentativa)
        db.session.commit()
    except SQLAlchemyError as erro:
        db.session.rollback()
        app.logger.exception('Falha ao excluir tentativa %s: %s', tentativa_id, erro)
        return jsonify({'erro': 'Não foi possível excluir a tentativa suspeita.'}), 500
    return jsonify({'ok': True})


@app.route('/api/escritorio/tentativas/excluir-lote', methods=['POST'])
@login_escritorio_obrigatorio
def excluir_tentativas_lote():
    data = request.get_json() or {}
    ids = data.get('ids') or []
    if not isinstance(ids, list) or not ids:
        return jsonify({'erro': 'Selecione ao menos um registro para excluir.'}), 400

    processos_ids = [p.id for p in Processo.query.filter_by(escritorio_id=request.escritorio.id).all()]
    try:
        removidos = TentativaContato.query.filter(
            TentativaContato.id.in_(ids),
            TentativaContato.processo_id.in_(processos_ids)
        ).delete(synchronize_session=False)
        db.session.commit()
    except SQLAlchemyError as erro:
        db.session.rollback()
        app.logger.exception('Falha ao excluir tentativas em lote: %s', erro)
        return jsonify({'erro': 'Não foi possível excluir os registros selecionados.'}), 500
    return jsonify({'ok': True, 'excluidos': removidos})


# ──────────────────────────────────────────────
# CLIENTES
# ──────────────────────────────────────────────

def _serializar_cliente(cliente, escritorio_id, processos_count=None):
    if processos_count is None:
        processos_count = db.session.query(func.count(Processo.id)).filter_by(
            cliente_id=cliente.id, escritorio_id=escritorio_id
        ).scalar() or 0
    return {
        'id': cliente.id,
        'nome': cliente.nome,
        'telefone': cliente.telefone,
        'email': cliente.email,
        'ativo': cliente.ativo,
        'processos_count': int(processos_count),
        'criado_em': cliente.criado_em.strftime('%d/%m/%Y') if cliente.criado_em else None
    }


def _clientes_do_escritorio_query(escritorio_id):
    cliente_ids = db.session.query(Processo.cliente_id).filter_by(escritorio_id=escritorio_id).distinct()
    return Cliente.query.filter(Cliente.id.in_(cliente_ids))


def _cliente_do_escritorio_ou_404(cliente_id, escritorio_id):
    """Só retorna o cliente se ele tiver ao menos um processo neste escritório."""
    pertence = Processo.query.filter_by(cliente_id=cliente_id, escritorio_id=escritorio_id).first()
    if not pertence:
        return None
    return db.session.get(Cliente, cliente_id)


@app.route('/api/escritorio/clientes', methods=['GET'])
@login_escritorio_obrigatorio
def listar_clientes():
    # Uma única consulta traz os clientes e a quantidade de processos deste escritório,
    # evitando uma consulta extra por cliente (N+1).
    lista = db.session.query(Cliente, func.count(Processo.id).label('processos_count')).join(
        Processo, Processo.cliente_id == Cliente.id
    ).filter(
        Processo.escritorio_id == request.escritorio.id
    ).group_by(Cliente.id).order_by(Cliente.nome.asc()).all()
    return jsonify([
        _serializar_cliente(cliente, request.escritorio.id, processos_count)
        for cliente, processos_count in lista
    ])


@app.route('/api/escritorio/clientes/<int:cliente_id>', methods=['PUT', 'DELETE'])
@login_escritorio_obrigatorio
def cliente_detalhe(cliente_id):
    cliente = _cliente_do_escritorio_ou_404(cliente_id, request.escritorio.id)
    if not cliente:
        return jsonify({'erro': 'Cliente não encontrado neste escritório.'}), 404

    if request.method == 'DELETE':
        data = request.get_json(silent=True) or {}
        if (data.get('confirmacao') or '').strip().upper() != 'EXCLUIR':
            return jsonify({'erro': 'Para excluir definitivamente, confirme digitando EXCLUIR.'}), 400
        try:
            removido_totalmente = _excluir_cliente_em_cascata(cliente, request.escritorio.id)
            db.session.commit()
        except SQLAlchemyError as erro:
            db.session.rollback()
            app.logger.exception('Falha ao excluir cliente %s: %s', cliente_id, erro)
            return jsonify({'erro': 'Não foi possível excluir o cliente. Nenhuma alteração foi salva.'}), 500
        mensagem = ('Cliente e todos os registros vinculados foram excluídos.' if removido_totalmente
                    else 'Os processos deste escritório com o cliente foram excluídos. O cadastro do '
                         'cliente foi preservado por também pertencer a outro escritório.')
        return jsonify({'ok': True, 'cliente_removido': removido_totalmente, 'mensagem': mensagem})

    if _cliente_possui_processos_de_outro_escritorio(cliente.id, request.escritorio.id):
        return jsonify({
            'erro': 'Este cliente está vinculado a mais de um escritório. Por segurança, dados globais do cliente não podem ser alterados por um único escritório.'
        }), 409

    data = request.get_json() or {}
    if 'nome' in data:
        if not isinstance(data['nome'], str) or not data['nome'].strip():
            return jsonify({'erro': 'Nome do cliente inválido.'}), 400
        cliente.nome = data['nome'].strip()
    if 'telefone' in data:
        if not isinstance(data['telefone'], str):
            return jsonify({'erro': 'Telefone do cliente inválido.'}), 400
        telefone = ''.join(filter(str.isdigit, data['telefone']))
        if len(telefone) < 8:
            return jsonify({'erro': 'Telefone do cliente inválido.'}), 400
        cliente.telefone = telefone
    if 'email' in data:
        if data['email'] is not None and not isinstance(data['email'], str):
            return jsonify({'erro': 'Email do cliente inválido.'}), 400
        cliente.email = (data['email'] or '').strip()
    db.session.commit()
    return jsonify(_serializar_cliente(cliente, request.escritorio.id))


@app.route('/api/escritorio/clientes/<int:cliente_id>/resumo-exclusao', methods=['GET'])
@login_escritorio_obrigatorio
def resumo_exclusao_cliente(cliente_id):
    cliente = _cliente_do_escritorio_ou_404(cliente_id, request.escritorio.id)
    if not cliente:
        return jsonify({'erro': 'Cliente não encontrado neste escritório.'}), 404

    processos_ids = [p.id for p in Processo.query.filter_by(cliente_id=cliente.id, escritorio_id=request.escritorio.id).all()]
    return jsonify({
        'processos': len(processos_ids),
        'tentativas_suspeitas': TentativaContato.query.filter(TentativaContato.processo_id.in_(processos_ids)).count() if processos_ids else 0,
        'contatos_seguros': ContatoSeguro.query.filter_by(cliente_id=cliente.id).count(),
        'compartilhado_com_outro_escritorio': _cliente_possui_processos_de_outro_escritorio(cliente.id, request.escritorio.id)
    })


@app.route('/api/escritorio/clientes/<int:cliente_id>/desativar', methods=['POST'])
@login_escritorio_obrigatorio
def desativar_cliente(cliente_id):
    cliente = _cliente_do_escritorio_ou_404(cliente_id, request.escritorio.id)
    if not cliente:
        return jsonify({'erro': 'Cliente não encontrado neste escritório.'}), 404
    if _cliente_possui_processos_de_outro_escritorio(cliente.id, request.escritorio.id):
        return jsonify({'erro': 'Cliente compartilhado entre escritórios; alteração global de status bloqueada por segurança.'}), 409
    cliente.ativo = False
    db.session.commit()
    return jsonify({'ok': True, 'ativo': cliente.ativo})


@app.route('/api/escritorio/clientes/<int:cliente_id>/reativar', methods=['POST'])
@login_escritorio_obrigatorio
def reativar_cliente(cliente_id):
    cliente = _cliente_do_escritorio_ou_404(cliente_id, request.escritorio.id)
    if not cliente:
        return jsonify({'erro': 'Cliente não encontrado neste escritório.'}), 404
    if _cliente_possui_processos_de_outro_escritorio(cliente.id, request.escritorio.id):
        return jsonify({'erro': 'Cliente compartilhado entre escritórios; alteração global de status bloqueada por segurança.'}), 409
    cliente.ativo = True
    db.session.commit()
    return jsonify({'ok': True, 'ativo': cliente.ativo})


# ──────────────────────────────────────────────
# CONTATO SEGURO ADVOGO — Código de Contato Autorizado (CCA)
# ──────────────────────────────────────────────

CANAIS_VALIDOS = ('whatsapp', 'ligacao', 'videochamada', 'email')
LABEL_CANAL = {
    'whatsapp': 'WhatsApp',
    'ligacao': 'ligação',
    'videochamada': 'videochamada',
    'email': 'e-mail'
}


def _serializar_cca_escritorio(c):
    """Serialização para o painel do escritório — aqui sim o código é exibido."""
    return {
        'id': c.id,
        'codigo_cca': c.codigo_cca,
        'advogado_nome': c.advogado.nome if c.advogado else None,
        'cliente_nome': c.cliente.nome if c.cliente else None,
        'processo_codigo': c.processo.codigo_unico if c.processo else None,
        'canal': c.canal,
        'status': c.status_atual(),
        'observacao': c.observacao,
        'expira_em': c.expira_em.strftime('%d/%m/%Y %H:%M:%S'),
        'usado_em': c.usado_em.strftime('%d/%m/%Y %H:%M:%S') if c.usado_em else None,
        'cancelado_em': c.cancelado_em.strftime('%d/%m/%Y %H:%M:%S') if c.cancelado_em else None,
        'criado_em': c.criado_em.strftime('%d/%m/%Y %H:%M:%S')
    }


@app.route('/api/escritorio/contato-seguro/iniciar', methods=['POST'])
@login_escritorio_obrigatorio
def iniciar_contato_seguro():
    """
    Gera um Código de Contato Autorizado (CCA) ANTES do advogado ligar/mensagear
    o cliente. O código nunca é informado ao cliente — ele só serve de registro
    interno consultado automaticamente pelo lado do cliente.
    """
    if not request.escritorio.plano_ativo():
        return jsonify({'erro': 'Plano inativo. Regularize o acesso para continuar.'}), 403

    data = request.get_json() or {}
    advogado_id = data.get('advogado_id')
    cliente_id = data.get('cliente_id')
    processo_id = data.get('processo_id')
    canal = data.get('canal', 'whatsapp')
    observacao = (data.get('observacao') or '').strip()[:300]

    if canal not in CANAIS_VALIDOS:
        return jsonify({'erro': 'Canal inválido. Use whatsapp, ligacao, videochamada ou email.'}), 400

    advogado = Advogado.query.filter_by(id=advogado_id, escritorio_id=request.escritorio.id).first()
    if not advogado:
        return jsonify({'erro': 'Advogado não encontrado neste escritório.'}), 404

    # cliente pode ser informado diretamente ou inferido a partir do processo
    processo = None
    if processo_id:
        processo = Processo.query.filter_by(id=processo_id, escritorio_id=request.escritorio.id).first()
        if not processo:
            return jsonify({'erro': 'Processo não encontrado neste escritório.'}), 404
        cliente_id = processo.cliente_id

    cliente = Cliente.query.filter_by(id=cliente_id).first()
    if not cliente:
        return jsonify({'erro': 'Cliente não encontrado.'}), 404

    # garante que o cliente pertence de fato a algum processo deste escritório
    vinculo = Processo.query.filter_by(escritorio_id=request.escritorio.id, cliente_id=cliente.id).first()
    if not vinculo:
        return jsonify({'erro': 'Este cliente não está vinculado ao seu escritório.'}), 403
    if not processo:
        processo = vinculo

    # cancela automaticamente qualquer CCA ainda ativo deste advogado com este cliente,
    # para nunca haver dois códigos simultâneos válidos
    cancelado_em = agora_utc()
    ContatoSeguro.query.filter_by(
        escritorio_id=request.escritorio.id, advogado_id=advogado.id,
        cliente_id=cliente.id, status='ativo'
    ).update(
        {'status': 'cancelado', 'cancelado_em': cancelado_em},
        synchronize_session=False
    )

    contato = ContatoSeguro(
        escritorio_id=request.escritorio.id,
        advogado_id=advogado.id,
        cliente_id=cliente.id,
        processo_id=processo.id if processo else None,
        codigo_cca=gerar_codigo_cca(),
        canal=canal,
        status='ativo',
        observacao=observacao,
        expira_em=agora_utc() + timedelta(minutes=CONTATO_SEGURO_TTL_MINUTOS)
    )
    db.session.add(contato)
    db.session.commit()

    return jsonify(_serializar_cca_escritorio(contato))


@app.route('/api/escritorio/contato-seguro/listar', methods=['GET'])
@login_escritorio_obrigatorio
def listar_contato_seguro():
    lista = ContatoSeguro.query.options(
        joinedload(ContatoSeguro.advogado),
        joinedload(ContatoSeguro.cliente),
        joinedload(ContatoSeguro.processo),
    ).filter_by(escritorio_id=request.escritorio.id) \
        .order_by(ContatoSeguro.criado_em.desc()).limit(100).all()
    return jsonify([_serializar_cca_escritorio(c) for c in lista])


@app.route('/api/escritorio/contato-seguro/cancelar/<int:contato_id>', methods=['POST'])
@login_escritorio_obrigatorio
def cancelar_contato_seguro(contato_id):
    contato = ContatoSeguro.query.filter_by(id=contato_id, escritorio_id=request.escritorio.id).first()
    if not contato:
        return jsonify({'erro': 'Contato seguro não encontrado.'}), 404
    if contato.status_atual() != 'ativo':
        return jsonify({'erro': 'Este contato já não está mais ativo.'}), 409

    contato.status = 'cancelado'
    contato.cancelado_em = agora_utc()
    db.session.commit()
    return jsonify({'ok': True})


@app.route('/api/escritorio/contato-seguro/reiniciar/<int:contato_id>', methods=['POST'])
@login_escritorio_obrigatorio
def reiniciar_contato_seguro(contato_id):
    """Cancela o CCA antigo e gera um novo, com nova validade de 10 minutos (Sprint 3)."""
    antigo = ContatoSeguro.query.filter_by(id=contato_id, escritorio_id=request.escritorio.id).first()
    if not antigo:
        return jsonify({'erro': 'Contato seguro não encontrado.'}), 404

    if antigo.status_atual() == 'ativo':
        antigo.status = 'cancelado'
        antigo.cancelado_em = agora_utc()

    novo = ContatoSeguro(
        escritorio_id=antigo.escritorio_id,
        advogado_id=antigo.advogado_id,
        cliente_id=antigo.cliente_id,
        processo_id=antigo.processo_id,
        codigo_cca=gerar_codigo_cca(),
        canal=antigo.canal,
        status='ativo',
        observacao=antigo.observacao,
        expira_em=agora_utc() + timedelta(minutes=CONTATO_SEGURO_TTL_MINUTOS)
    )
    db.session.add(novo)
    db.session.commit()
    return jsonify(_serializar_cca_escritorio(novo))


@app.route('/api/escritorio/contato-seguro/limpar-expirados', methods=['POST'])
@login_escritorio_obrigatorio
def limpar_expirados_contato_seguro():
    """
    Marca formalmente como 'expirado' todo CCA vencido (apenas atualiza o status
    salvo no banco — nada é apagado, conforme exigido).
    """
    agora = agora_utc()
    marcados = ContatoSeguro.query.filter_by(
        escritorio_id=request.escritorio.id, status='ativo'
    ).filter(ContatoSeguro.expira_em < agora).update(
        {'status': 'expirado'}, synchronize_session=False
    )
    db.session.commit()
    return jsonify({'ok': True, 'marcados_como_expirados': int(marcados or 0)})


@app.route('/api/escritorio/contato-seguro/<int:contato_id>', methods=['DELETE'])
@login_escritorio_obrigatorio
def excluir_contato_seguro(contato_id):
    contato = ContatoSeguro.query.filter_by(id=contato_id, escritorio_id=request.escritorio.id).first()
    if not contato:
        return jsonify({'erro': 'Contato seguro não encontrado.'}), 404
    try:
        _excluir_contatos_seguros_em_lote([contato.id])
        db.session.commit()
    except SQLAlchemyError as erro:
        db.session.rollback()
        app.logger.exception('Falha ao excluir contato seguro %s: %s', contato_id, erro)
        return jsonify({'erro': 'Não foi possível excluir este Contato Seguro.'}), 500
    return jsonify({'ok': True})


@app.route('/api/escritorio/contato-seguro/excluir-lote', methods=['POST'])
@login_escritorio_obrigatorio
def excluir_contato_seguro_lote():
    data = request.get_json() or {}
    ids = data.get('ids') or []
    if not isinstance(ids, list) or not ids:
        return jsonify({'erro': 'Selecione ao menos um registro para excluir.'}), 400

    ids_do_escritorio = [
        c.id for c in ContatoSeguro.query.filter(
            ContatoSeguro.id.in_(ids), ContatoSeguro.escritorio_id == request.escritorio.id
        ).all()
    ]
    if not ids_do_escritorio:
        return jsonify({'erro': 'Nenhum dos registros selecionados foi encontrado.'}), 404
    try:
        _excluir_contatos_seguros_em_lote(ids_do_escritorio)
        db.session.commit()
    except SQLAlchemyError as erro:
        db.session.rollback()
        app.logger.exception('Falha ao excluir contatos seguros em lote: %s', erro)
        return jsonify({'erro': 'Não foi possível excluir os registros selecionados.'}), 500
    return jsonify({'ok': True, 'excluidos': len(ids_do_escritorio)})


# ──────────────────────────────────────────────
# ROTAS — CLIENTE FINAL (B2C)
# ──────────────────────────────────────────────

@app.route('/api/cliente/login', methods=['POST'])
def login_cliente():
    data = request.get_json() or {}
    telefone = ''.join(filter(str.isdigit, (data.get('telefone') or ''))) 
    senha = data.get('senha') or ''

    permitido, espera = verificar_rate_limit(telefone)
    if not permitido:
        return jsonify({'erro': f'Muitas tentativas de login. Tente novamente em {espera} segundos.'}), 429

    cliente = Cliente.query.filter_by(telefone=telefone).first()
    if not cliente or not verificar_senha(cliente.senha_hash, senha):
        registrar_tentativa_falha(telefone)
        return jsonify({'erro': 'Telefone ou senha incorretos'}), 401
    if not cliente.ativo:
        return jsonify({'erro': 'Acesso do cliente desativado. Entre em contato com o escritório responsável.'}), 403

    limpar_tentativas(telefone)
    if len(cliente.senha_hash) == 64 and ':' not in cliente.senha_hash:
        cliente.senha_hash = hash_senha(senha)
        db.session.commit()

    return _resposta_com_sessao(
        {'nome': cliente.nome},
        {'id': cliente.id, 'tipo': 'cliente'},
        cliente.senha_hash
    )


@app.route('/api/cliente/processos', methods=['GET'])
@login_cliente_obrigatorio
def processos_do_cliente():
    lista = Processo.query.options(
        joinedload(Processo.advogado),
        joinedload(Processo.escritorio),
    ).filter_by(cliente_id=request.cliente.id, status='ativo').all()
    return jsonify([{
        'id': p.id, 'codigo_unico': p.codigo_unico, 'numero_processo': p.numero_processo,
        'advogado_nome': p.advogado.nome if p.advogado else None,
        'escritorio_nome': p.escritorio.nome
    } for p in lista])


# ──────────────────────────────────────────────
# PRIVACIDADE / DIREITOS DO TITULAR
# ──────────────────────────────────────────────

@app.route('/api/cliente/privacidade/exportar', methods=['GET'])
@login_cliente_obrigatorio
def cliente_privacidade_exportar():
    cliente = request.cliente
    processos = Processo.query.options(
        joinedload(Processo.advogado),
        joinedload(Processo.escritorio),
    ).filter_by(cliente_id=cliente.id).order_by(Processo.criado_em.asc()).all()
    verificacoes = Verificacao.query.filter_by(cliente_id=cliente.id).order_by(
        Verificacao.criado_em.asc()
    ).all()
    return jsonify({
        'gerado_em': agora_utc().isoformat(),
        'titular': {
            'nome': cliente.nome,
            'telefone': cliente.telefone,
            'email': cliente.email,
            'ativo': bool(cliente.ativo),
            'criado_em': cliente.criado_em.isoformat() if cliente.criado_em else None,
        },
        'processos': [{
            'codigo_unico': p.codigo_unico,
            'numero_processo': p.numero_processo,
            'descricao': p.descricao,
            'status': p.status,
            'escritorio_nome': p.escritorio.nome if p.escritorio else None,
            'advogado_nome': p.advogado.nome if p.advogado else None,
            'criado_em': p.criado_em.isoformat() if p.criado_em else None,
        } for p in processos],
        'verificacoes': [{
            'numero_consultado': v.numero_consultado,
            'codigo_consultado': v.codigo_consultado,
            'resultado': v.resultado,
            'criado_em': v.criado_em.isoformat() if v.criado_em else None,
        } for v in verificacoes],
    })


@app.route('/api/cliente/privacidade/solicitacoes', methods=['GET', 'POST'])
@login_cliente_obrigatorio
def cliente_privacidade_solicitacoes():
    referencia = _referencia_privacidade('cliente', request.cliente.id)
    if request.method == 'GET':
        itens = SolicitacaoPrivacidade.query.filter_by(
            referencia_titular=referencia, titular_tipo='cliente'
        ).order_by(SolicitacaoPrivacidade.criado_em.desc()).all()
        return jsonify([_serializar_solicitacao_privacidade(i) for i in itens])

    item, erro = _criar_solicitacao_privacidade(
        'cliente', request.cliente.id, request.get_json() or {}
    )
    if erro:
        return jsonify({'erro': erro}), 400
    return jsonify({
        'ok': True,
        'solicitacao': _serializar_solicitacao_privacidade(item),
        'mensagem': (
            'Solicitação registrada. O pedido será analisado conforme a finalidade '
            'do tratamento, obrigações aplicáveis e direitos previstos na LGPD.'
        )
    }), 201


@app.route('/api/escritorio/privacidade/exportar', methods=['GET'])
@login_escritorio_obrigatorio
def escritorio_privacidade_exportar():
    escritorio = request.escritorio
    advogados = Advogado.query.filter_by(escritorio_id=escritorio.id).order_by(
        Advogado.criado_em.asc()
    ).all()
    return jsonify({
        'gerado_em': agora_utc().isoformat(),
        'conta': {
            'nome': escritorio.nome,
            'cnpj': escritorio.cnpj,
            'email': escritorio.email,
            'plano': escritorio.plano,
            'plano_expira': escritorio.plano_expira.isoformat() if escritorio.plano_expira else None,
            'criado_em': escritorio.criado_em.isoformat() if escritorio.criado_em else None,
        },
        'advogados': [{
            'nome': a.nome,
            'oab': a.oab,
            'telefone_oficial': a.telefone_oficial,
            'foto_url': _url_foto_banco(a),
            'ativo': bool(a.ativo),
            'criado_em': a.criado_em.isoformat() if a.criado_em else None,
        } for a in advogados],
    })


@app.route('/api/escritorio/privacidade/solicitacoes', methods=['GET', 'POST'])
@login_escritorio_obrigatorio
def escritorio_privacidade_solicitacoes():
    referencia = _referencia_privacidade('escritorio', request.escritorio.id)
    if request.method == 'GET':
        itens = SolicitacaoPrivacidade.query.filter_by(
            referencia_titular=referencia, titular_tipo='escritorio'
        ).order_by(SolicitacaoPrivacidade.criado_em.desc()).all()
        return jsonify([_serializar_solicitacao_privacidade(i) for i in itens])

    item, erro = _criar_solicitacao_privacidade(
        'escritorio', request.escritorio.id, request.get_json() or {}
    )
    if erro:
        return jsonify({'erro': erro}), 400
    return jsonify({'ok': True, 'solicitacao': _serializar_solicitacao_privacidade(item)}), 201


# ──────────────────────────────────────────────
# CONTATO SEGURO ADVOGO — lado do cliente
# ──────────────────────────────────────────────

TIPOS_SOLICITACAO_PRIVACIDADE = {
    'acesso',
    'correcao',
    'anonimizacao',
    'bloqueio',
    'exclusao',
    'portabilidade',
    'oposicao',
    'revogacao_consentimento',
    'informacoes_compartilhamento',
}


def _referencia_privacidade(titular_tipo, titular_id):
    mensagem = f'{titular_tipo}:{int(titular_id)}'.encode('utf-8')
    chave = app.config['SECRET_KEY'].encode('utf-8')
    return hmac.new(chave, mensagem, hashlib.sha256).hexdigest()


def _pseudonimizar_ip(ip):
    ip = (ip or '').strip()
    if not ip:
        return None
    if ip.startswith('h:') and len(ip) > 10:
        return ip
    chave = app.config['SECRET_KEY'].encode('utf-8')
    digest = hmac.new(chave, ip.encode('utf-8'), hashlib.sha256).hexdigest()
    return 'h:' + digest[:48]


def _ip_cliente():
    bruto = request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()
    return _pseudonimizar_ip(bruto)


def _migrar_ips_legados_para_hash():
    """Pseudonimiza IPs históricos; o IP bruto deixa de ficar persistido."""
    alterados = 0
    inspetor = inspect(db.engine)
    for modelo in (ContatoSeguroLog, AcessoPublicoLog):
        if not inspetor.has_table(modelo.__tablename__):
            continue
        registros = modelo.query.filter(
            modelo.ip.isnot(None),
            ~modelo.ip.like('h:%')
        ).all()
        for registro in registros:
            registro.ip = _pseudonimizar_ip(registro.ip)
            alterados += 1
    if alterados:
        db.session.commit()
        app.logger.info('[LGPD] %s IP(s) histórico(s) pseudonimizado(s).', alterados)
    return alterados


def _aplicar_retencao_logs_privacidade(dias=None):
    """Aplica retenção somente quando um período positivo for explicitamente definido."""
    dias = LGPD_RETENCAO_LOGS_DIAS if dias is None else int(dias)
    if dias <= 0:
        return {'contatos_seguros_logs': 0, 'acessos_publicos_logs': 0}
    limite = agora_utc() - timedelta(days=dias)
    removidos_contato = ContatoSeguroLog.query.filter(
        ContatoSeguroLog.criado_em < limite
    ).delete(synchronize_session=False)
    removidos_publico = AcessoPublicoLog.query.filter(
        AcessoPublicoLog.criado_em < limite
    ).delete(synchronize_session=False)
    db.session.commit()
    return {
        'contatos_seguros_logs': int(removidos_contato or 0),
        'acessos_publicos_logs': int(removidos_publico or 0),
    }


def _criar_solicitacao_privacidade(titular_tipo, titular_id, data):
    tipo = (data.get('tipo') or '').strip().lower()
    detalhes = (data.get('detalhes') or '').strip()[:500]
    if tipo not in TIPOS_SOLICITACAO_PRIVACIDADE:
        return None, 'Tipo de solicitação de privacidade inválido.'
    item = SolicitacaoPrivacidade(
        referencia_titular=_referencia_privacidade(titular_tipo, titular_id),
        titular_tipo=titular_tipo,
        tipo=tipo,
        status='recebida',
        detalhes=detalhes or None,
        criado_em=agora_utc(),
        atualizado_em=agora_utc(),
    )
    db.session.add(item)
    db.session.commit()
    return item, None


def _serializar_solicitacao_privacidade(item):
    return {
        'id': item.id,
        'tipo': item.tipo,
        'status': item.status,
        'detalhes': item.detalhes,
        'criado_em': item.criado_em.isoformat() if item.criado_em else None,
        'atualizado_em': item.atualizado_em.isoformat() if item.atualizado_em else None,
    }


@app.route('/api/cliente/contato-seguro/ativo', methods=['GET'])
@login_cliente_obrigatorio
def contato_seguro_ativo():
    """
    O cliente nunca informa nada aqui — só consulta. Retorna o contato autorizado
    ativo mais recente para ele, se existir, sem nunca aceitar um código vencido.
    """
    agora = agora_utc()
    contato = ContatoSeguro.query.filter_by(cliente_id=request.cliente.id, status='ativo') \
        .filter(ContatoSeguro.expira_em > agora) \
        .order_by(ContatoSeguro.criado_em.desc()).first()

    # auditoria: toda consulta é registrada, mesmo sem resultado
    db.session.add(ContatoSeguroLog(
        cliente_id=request.cliente.id,
        contato_seguro_id=contato.id if contato else None,
        encontrado_ativo=bool(contato),
        ip=_ip_cliente()
    ))

    if contato and not contato.usado_em:
        contato.usado_em = agora
    db.session.commit()

    if not contato:
        return jsonify({'ativo': False})

    return jsonify({
        'ativo': True,
        'advogado_nome': contato.advogado.nome if contato.advogado else 'seu advogado',
        'escritorio_nome': contato.escritorio.nome if contato.escritorio else None,
        'canal': contato.canal,
        'iniciado_em': contato.criado_em.strftime('%H:%M'),
        'expira_em': contato.expira_em.strftime('%H:%M')
    })


@app.route('/api/cliente/contato-seguro/verificar', methods=['POST'])
@login_cliente_obrigatorio
def contato_seguro_verificar():
    """
    Mesma lógica de /ativo, mas pensada para o botão 'Verificar contato agora'
    e que também aceita o sinalizador de pedido de pagamento, elevando o risco.
    """
    data = request.get_json() or {}
    pediu_pagamento = bool(data.get('pediu_pagamento', False))

    agora = agora_utc()
    contato = ContatoSeguro.query.filter_by(cliente_id=request.cliente.id, status='ativo') \
        .filter(ContatoSeguro.expira_em > agora) \
        .order_by(ContatoSeguro.criado_em.desc()).first()

    db.session.add(ContatoSeguroLog(
        cliente_id=request.cliente.id,
        contato_seguro_id=contato.id if contato else None,
        encontrado_ativo=bool(contato),
        ip=_ip_cliente()
    ))
    if contato and not contato.usado_em:
        contato.usado_em = agora

    if contato:
        resultado = 'confirmado'
        alerta_nivel = 'nenhum'
        mensagem = (
            f'Contato confirmado. Este contato foi iniciado por {contato.advogado.nome} '
            f'({contato.escritorio.nome}) às {contato.criado_em.strftime("%H:%M")} pelo canal '
            f'{LABEL_CANAL.get(contato.canal, contato.canal)}. Mesmo assim, nunca envie dinheiro '
            f'sem confirmar novamente pelo canal oficial do escritório.'
        )
        if pediu_pagamento:
            mensagem += (' ⚠️ Atenção: mesmo com contato confirmado, advogados não pedem pagamento '
                         'via Pix/transferência para liberar valores de processo.')
            alerta_nivel = 'medio'
    else:
        resultado = 'nao_encontrado'
        alerta_nivel = 'alto'
        mensagem = ('Não existe contato autorizado neste momento. Não envie dinheiro, não mande '
                    'documentos e não continue a conversa. Pode ser tentativa de golpe.')
        if pediu_pagamento:
            alerta_nivel = 'alto'

        # registra automaticamente como tentativa suspeita no primeiro processo ativo do cliente
        processo_ref = Processo.query.filter_by(cliente_id=request.cliente.id).order_by(Processo.criado_em.desc()).first()
        if processo_ref:
            db.session.add(TentativaContato(
                processo_id=processo_ref.id,
                canal=data.get('canal', 'whatsapp'),
                descricao='Cliente verificou Contato Seguro e NÃO havia CCA ativo no momento.',
                confirmado_golpe=pediu_pagamento
            ))

    db.session.commit()
    return jsonify({'resultado': resultado, 'alerta_nivel': alerta_nivel, 'mensagem': mensagem})


@app.route('/api/cliente/contato-seguro/registrar-suspeita', methods=['POST'])
@login_cliente_obrigatorio
def contato_seguro_registrar_suspeita():
    """Botão 'Registrar tentativa suspeita' na área do cliente — não exige contato ativo nem dados sensíveis."""
    data = request.get_json() or {}
    processo_ref = Processo.query.filter_by(cliente_id=request.cliente.id).order_by(Processo.criado_em.desc()).first()
    if not processo_ref:
        return jsonify({'erro': 'Nenhum processo vinculado ao seu cadastro para registrar a tentativa.'}), 404

    db.session.add(TentativaContato(
        processo_id=processo_ref.id,
        numero_suspeito=data.get('numero', ''),
        canal=data.get('canal', 'whatsapp'),
        descricao=data.get('descricao', 'Tentativa suspeita registrada pelo cliente via Contato Seguro.'),
        confirmado_golpe=True
    ))
    db.session.commit()
    return jsonify({'ok': True, 'mensagem': 'Tentativa suspeita registrada. Seu escritório foi notificado no painel.'})


@app.route('/api/cliente/verificar', methods=['POST'])
@login_cliente_obrigatorio
def verificar_contato():
    """
    Núcleo do produto: cliente cola o número que entrou em contato
    (ou o código do caso) e o sistema confirma se é legítimo.
    """
    data = request.get_json() or {}
    numero = ''.join(filter(str.isdigit, (data.get('numero') or ''))) 
    codigo = (data.get('codigo') or '').strip().upper()
    canal = data.get('canal', 'whatsapp')
    pediu_pagamento = data.get('pediu_pagamento', False)

    processo = None
    if codigo:
        processo = Processo.query.filter_by(
            codigo_unico=codigo, cliente_id=request.cliente.id
        ).first()

    if not processo:
        processos_cliente = Processo.query.filter_by(cliente_id=request.cliente.id).all()
        for p in processos_cliente:
            if p.advogado and ''.join(filter(str.isdigit, p.advogado.telefone_oficial)) == numero:
                processo = p
                break

    resultado = 'nao_encontrado'
    mensagem = 'Não encontramos esse contato vinculado aos seus processos. Atenção: pode ser tentativa de golpe.'
    alerta_nivel = 'alto'

    if processo:
        numero_oficial = ''.join(filter(str.isdigit, processo.advogado.telefone_oficial)) if processo.advogado else ''
        if numero == numero_oficial:
            resultado = 'confirmado'
            mensagem = f'Confirmado! Este é o número oficial de {processo.advogado.nome} ({processo.escritorio.nome}).'
            alerta_nivel = 'nenhum'
        else:
            resultado = 'numero_diferente'
            mensagem = f'Atenção: o código do processo é válido, mas esse número NÃO é o oficial de {processo.advogado.nome}. Pode ser golpe.'
            alerta_nivel = 'alto'

    if pediu_pagamento:
        mensagem += ' ⚠️ Advogados não pedem pagamento via Pix/transferência para liberar valores de processo. Isso é sinal forte de golpe.'
        alerta_nivel = 'alto'

    verificacao = Verificacao(
        cliente_id=request.cliente.id,
        numero_consultado=numero,
        codigo_consultado=codigo,
        resultado=resultado
    )
    db.session.add(verificacao)

    if processo and resultado != 'confirmado':
        tentativa = TentativaContato(
            processo_id=processo.id,
            numero_suspeito=numero,
            canal=canal,
            descricao=data.get('descricao', ''),
            confirmado_golpe=(resultado == 'numero_diferente')
        )
        db.session.add(tentativa)

    db.session.commit()

    return jsonify({
        'resultado': resultado,
        'mensagem': mensagem,
        'alerta_nivel': alerta_nivel
    })


# ──────────────────────────────────────────────
# PAINEL DO CLIENTE SEM LOGIN — link seguro por token (Sprint 3)
# ──────────────────────────────────────────────

def _ip_requisicao():
    bruto = request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()
    return _pseudonimizar_ip(bruto)


def _avatar_iniciais(nome):
    """Gera iniciais para avatar padrão quando o advogado não tem foto."""
    partes = (nome or '').strip().split()
    if not partes:
        return '??'
    if len(partes) == 1:
        return partes[0][:2].upper()
    return (partes[0][0] + partes[-1][0]).upper()


@app.route('/api/cliente-publico/contato-seguro/<token>', methods=['GET'])
def contato_seguro_publico(token):
    """
    Rota pública e segura: NÃO lista clientes, NÃO aceita busca por nome/telefone —
    só funciona com o token exato, longo e aleatório, gerado na criação do processo.
    """
    processo = Processo.query.filter_by(token_cliente=token).first()

    db.session.add(AcessoPublicoLog(
        processo_id=processo.id if processo else None,
        acao='visualizou',
        ip=_ip_requisicao()
    ))
    db.session.commit()

    if not processo:
        # mensagem genérica — nunca revela se o token "quase" existe
        return jsonify({'valido': False, 'mensagem': 'Link inválido ou expirado.'}), 404

    agora = agora_utc()
    cca_ativo = ContatoSeguro.query.filter_by(processo_id=processo.id, status='ativo') \
        .filter(ContatoSeguro.expira_em > agora).order_by(ContatoSeguro.criado_em.desc()).first()

    advogado = processo.advogado
    return jsonify({
        'valido': True,
        'escritorio_nome': processo.escritorio.nome,
        'advogado_nome': advogado.nome if advogado else None,
        'advogado_oab': advogado.oab if advogado else None,
        'advogado_foto_url': _url_foto_banco(advogado) if advogado else None,
        'advogado_iniciais': _avatar_iniciais(advogado.nome if advogado else ''),
        'advogado_telefone_oficial': advogado.telefone_oficial if advogado else None,
        'contato_ativo': bool(cca_ativo),
        'canal_autorizado': cca_ativo.canal if cca_ativo else None,
        'iniciado_em': cca_ativo.criado_em.strftime('%H:%M') if cca_ativo else None
    })


@app.route('/api/cliente-publico/registrar-alerta/<token>', methods=['POST'])
def registrar_alerta_publico(token):
    """
    Botões 'Não reconheço esse contato' / 'Pediram dinheiro/Pix' / tentativa suspeita,
    acessíveis sem login. Sempre responde de forma genérica para não confirmar
    nem negar a existência do token a quem está só "tentando a sorte".
    """
    processo = Processo.query.filter_by(token_cliente=token).first()
    data = request.get_json() or {}
    tipo = data.get('tipo', 'nao_reconheco')  # nao_reconheco | pix | suspeita_geral

    db.session.add(AcessoPublicoLog(
        processo_id=processo.id if processo else None,
        acao=tipo,
        ip=_ip_requisicao()
    ))

    if processo:
        db.session.add(TentativaContato(
            processo_id=processo.id,
            numero_suspeito=data.get('numero', ''),
            canal=data.get('canal', 'whatsapp'),
            descricao=data.get('descricao') or f'Alerta registrado pelo cliente via link seguro ({tipo}).',
            confirmado_golpe=(tipo == 'pix')
        ))

    db.session.commit()

    mensagens = {
        'pix': 'Alerta de golpe. Não envie dinheiro agora. Golpistas costumam pedir Pix, taxa ou pagamento '
               'urgente para liberar valores. Confirme somente pelo canal oficial do escritório.',
        'nao_reconheco': 'Aviso registrado. Seu escritório foi notificado sobre esse contato não reconhecido.',
        'suspeita_geral': 'Aviso registrado. Seu escritório foi notificado.'
    }
    return jsonify({
        'ok': True,
        'mensagem': mensagens.get(tipo, mensagens['suspeita_geral']),
        'risco': 'alto' if tipo == 'pix' else 'medio'
    })


@app.route('/api/cliente-publico/seguro/<token>', methods=['GET'])
def cliente_publico_seguro(token):
    """
    Alias de leitura completa do painel do cliente (mesmo contrato de dados de
    /api/cliente-publico/contato-seguro/<token>) — nome de rota alinhado ao
    briefing mais recente. Mantido como rota própria para não depender de
    redirect e para já existir caso o nome 'seguro' seja o esperado por outra
    integração futura.
    """
    return contato_seguro_publico(token)


@app.route('/api/cliente-publico/contato-ativo/<token>', methods=['GET'])
def cliente_publico_contato_ativo(token):
    """Versão enxuta: só responde se há (ou não) contato autorizado ativo agora, sem os demais dados do advogado."""
    processo = Processo.query.filter_by(token_cliente=token).first()

    db.session.add(AcessoPublicoLog(
        processo_id=processo.id if processo else None,
        acao='consultou_ativo',
        ip=_ip_requisicao()
    ))
    db.session.commit()

    if not processo:
        return jsonify({'valido': False, 'mensagem': 'Link inválido ou expirado.'}), 404

    agora = agora_utc()
    cca_ativo = ContatoSeguro.query.filter_by(processo_id=processo.id, status='ativo') \
        .filter(ContatoSeguro.expira_em > agora).order_by(ContatoSeguro.criado_em.desc()).first()

    return jsonify({
        'valido': True,
        'contato_ativo': bool(cca_ativo),
        'canal_autorizado': cca_ativo.canal if cca_ativo else None,
        'iniciado_em': cca_ativo.criado_em.strftime('%H:%M') if cca_ativo else None,
        'expira_em': cca_ativo.expira_em.strftime('%H:%M') if cca_ativo else None
    })


@app.route('/api/cliente-publico/analisar-golpe/<token>', methods=['POST'])
def cliente_publico_analisar_golpe(token):
    """
    IA Anti-Golpe já vinculada ao token do cliente (em vez do endpoint genérico
    /api/ia/analisar-golpe) — assim a tentativa suspeita de alto risco já é
    registrada automaticamente no processo correto, sem o cliente precisar
    informar nenhum código.
    """
    processo = Processo.query.filter_by(token_cliente=token).first()
    if not processo:
        return jsonify({'valido': False, 'mensagem': 'Link inválido ou expirado.'}), 404

    data = request.get_json() or {}
    texto_mensagem = data.get('texto_mensagem', '')
    pediu_pagamento = bool(data.get('pediu_pagamento', False))

    if not texto_mensagem and not pediu_pagamento:
        return jsonify({'erro': 'Cole a mensagem recebida para analisar.'}), 400

    resultado = analisar_golpe_local(texto_mensagem, pediu_pagamento=pediu_pagamento)

    db.session.add(AcessoPublicoLog(processo_id=processo.id, acao='analisou_ia', ip=_ip_requisicao()))
    if resultado['pontuacao'] >= 45:
        db.session.add(TentativaContato(
            processo_id=processo.id,
            canal=data.get('canal', 'whatsapp'),
            descricao=f"[IA Anti-Golpe via link seguro — risco {resultado['risco']}] {texto_mensagem[:400]}",
            confirmado_golpe=(resultado['pontuacao'] >= 70)
        ))
    db.session.commit()

    return jsonify(resultado)


# ──────────────────────────────────────────────
# VERIFICAÇÃO PÚBLICA (sem login — landing page)
# ──────────────────────────────────────────────

@app.route('/api/publico/verificar', methods=['POST'])
def verificar_contato_publico():
    """
    Verificação rápida sem necessidade de login do cliente.
    Requer o código do processo (compartilhado pelo escritório) + número de contato.
    """
    permitido, espera = verificar_limite_acao('verificacao-publica', 30, 60)
    if not permitido:
        return jsonify({'erro': f'Muitas verificações. Tente novamente em {espera} segundos.'}), 429
    data = request.get_json() or {}
    numero = ''.join(filter(str.isdigit, (data.get('numero') or ''))) 
    codigo = (data.get('codigo') or '').strip().upper()
    canal = data.get('canal', 'whatsapp')
    pediu_pagamento = data.get('pediu_pagamento', False)

    if not codigo:
        return jsonify({'erro': 'Informe o código do processo para verificar.'}), 400

    processo = Processo.query.filter_by(codigo_unico=codigo).first()

    resultado = 'nao_encontrado'
    mensagem = 'Código de processo não encontrado. Atenção: confirme o código diretamente com o escritório, pode ser tentativa de golpe.'
    alerta_nivel = 'alto'

    if processo:
        numero_oficial = ''.join(filter(str.isdigit, processo.advogado.telefone_oficial)) if processo.advogado else ''
        if numero == numero_oficial:
            resultado = 'confirmado'
            mensagem = f'Confirmado! Este é o número oficial de {processo.advogado.nome} ({processo.escritorio.nome}).'
            alerta_nivel = 'nenhum'
        else:
            resultado = 'numero_diferente'
            mensagem = f'Atenção: o código do processo é válido, mas esse número NÃO é o oficial de {processo.advogado.nome}. Pode ser golpe.'
            alerta_nivel = 'alto'

    if pediu_pagamento:
        mensagem += ' ⚠️ Advogados não pedem pagamento via Pix/transferência para liberar valores de processo. Isso é sinal forte de golpe.'
        alerta_nivel = 'alto'

    if processo and resultado != 'confirmado':
        tentativa = TentativaContato(
            processo_id=processo.id,
            numero_suspeito=numero,
            canal=canal,
            descricao=data.get('descricao', ''),
            confirmado_golpe=(resultado == 'numero_diferente')
        )
        db.session.add(tentativa)
        db.session.commit()

    return jsonify({
        'resultado': resultado,
        'mensagem': mensagem,
        'alerta_nivel': alerta_nivel
    })


# ──────────────────────────────────────────────
# IA ANTI-GOLPE (Sprint 3)
# ──────────────────────────────────────────────
# Motor local por regras, sem dependência externa. Preparado para, no futuro,
# delegar a análise a um provedor de IA (OpenAI/Anthropic/Gemini) caso as
# variáveis de ambiente IA_PROVEDOR e IA_API_KEY sejam configuradas — ver
# função analisar_golpe_local() como ponto único de substituição.

IA_PROVEDOR = os.environ.get('IA_PROVEDOR', '')  # '' = usa motor local por regras
IA_API_KEY = os.environ.get('IA_API_KEY', '')

SINAIS_GOLPE = [
    # (palavras-chave, peso, rótulo legível)
    (['pix', 'transferência', 'transferencia', 'depósito', 'deposito'], 25, 'Pedido de Pix/transferência'),
    (['taxa', 'custas', 'liberação', 'liberacao', 'desbloqueio', 'alvará', 'alvara'], 22, 'Taxa para liberar valor/alvará'),
    (['urgente', 'agora', 'rápido', 'rapido', 'imediatamente', 'hoje mesmo'], 12, 'Urgência incomum'),
    (['bloqueado', 'bloqueio', 'valor disponível', 'valor disponivel', 'indenização', 'indenizacao'], 15, 'Promessa de valor bloqueado/disponível'),
    (['senha', 'conta bancária', 'conta bancaria', 'cartão', 'cartao', 'cvv', 'dados bancários', 'dados bancarios'], 25, 'Pedido de dados bancários/senha'),
    (['documento', 'cpf', 'rg', 'foto do documento'], 10, 'Pedido de documentos pessoais'),
    (['vai perder', 'última chance', 'ultima chance', 'se não pagar', 'se nao pagar', 'processo será cancelado'], 18, 'Ameaça ou pressão emocional'),
    (['fórum', 'forum', 'cartório', 'cartorio', 'banco central', 'receita federal', 'tribunal'], 10, 'Cita instituição para gerar autoridade falsa'),
]


def analisar_golpe_local(texto, numero_suspeito='', pediu_pagamento=False, numero_oficial_bate=None):
    """
    Motor de regras: cada sinal de risco encontrado soma pontos (0-100).
    numero_oficial_bate: True/False/None — se já se sabe se o número confere com o oficial.
    """
    texto_lower = (texto or '').lower()
    pontuacao = 0
    sinais_detectados = []

    for palavras, peso, rotulo in SINAIS_GOLPE:
        if any(p in texto_lower for p in palavras):
            pontuacao += peso
            sinais_detectados.append(rotulo)

    if pediu_pagamento:
        pontuacao += 20
        if 'Pedido de Pix/transferência' not in sinais_detectados:
            sinais_detectados.append('Pedido de pagamento confirmado pelo cliente')

    if numero_oficial_bate is False:
        pontuacao += 20
        sinais_detectados.append('Número diferente do oficial cadastrado')

    pontuacao = min(pontuacao, 100)

    if pontuacao >= 70:
        risco = 'crítico'
    elif pontuacao >= 45:
        risco = 'alto'
    elif pontuacao >= 20:
        risco = 'médio'
    else:
        risco = 'baixo'

    mensagens_cliente = {
        'crítico': 'Risco crítico de golpe. Não envie dinheiro, documentos ou dados pessoais. Desligue e confirme direto com o escritório pelo canal oficial.',
        'alto': 'Alto risco de golpe. Não envie dinheiro nem dados. Confirme esse contato pelo canal oficial do escritório antes de continuar.',
        'médio': 'Atenção: esse contato tem sinais suspeitos. Tenha cuidado e confirme antes de continuar a conversa.',
        'baixo': 'Não foram identificados sinais fortes de golpe nesta mensagem, mas mantenha a cautela e nunca envie dados bancários sem confirmar.'
    }
    mensagens_escritorio = {
        'crítico': 'Cliente recebeu mensagem com múltiplos sinais de golpe (pagamento + urgência/ameaça). Recomenda-se contato imediato com o cliente.',
        'alto': 'Mensagem recebida pelo cliente apresenta sinais relevantes de fraude. Recomenda-se verificar e orientar o cliente.',
        'médio': 'Mensagem com alguns sinais de atenção. Acompanhar se houver novas tentativas.',
        'baixo': 'Sem sinais fortes de fraude identificados pelo motor de regras.'
    }

    return {
        'risco': risco,
        'pontuacao': pontuacao,
        'sinais_detectados': sinais_detectados,
        'recomendacao': 'Não prosseguir sem confirmação pelo canal oficial' if pontuacao >= 45 else 'Manter cautela padrão',
        'mensagem_para_cliente': mensagens_cliente[risco],
        'mensagem_para_escritorio': mensagens_escritorio[risco],
        'motor': 'regras_locais' if not IA_PROVEDOR else IA_PROVEDOR
    }


@app.route('/api/ia/analisar-golpe', methods=['POST'])
def analisar_golpe():
    """
    Endpoint público de análise (o cliente pode usar tanto logado quanto pelo
    link sem login). Não expõe dados de outros clientes — analisa apenas o
    texto enviado nesta própria requisição.
    """
    data = request.get_json() or {}
    texto_mensagem = data.get('texto_mensagem', '')
    numero_suspeito = data.get('numero_suspeito', '')
    canal = data.get('canal', 'whatsapp')
    pediu_pagamento = bool(data.get('pediu_pagamento', False))
    codigo_processo = data.get('codigo_processo', '')

    if not texto_mensagem and not pediu_pagamento:
        return jsonify({'erro': 'Informe o texto da mensagem recebida ou marque se houve pedido de pagamento.'}), 400

    numero_oficial_bate = None
    processo = None
    if codigo_processo:
        processo = Processo.query.filter_by(codigo_unico=codigo_processo.strip().upper()).first()
    if processo and processo.advogado and numero_suspeito:
        numero_digitos = ''.join(filter(str.isdigit, numero_suspeito))
        oficial_digitos = ''.join(filter(str.isdigit, processo.advogado.telefone_oficial))
        numero_oficial_bate = (numero_digitos == oficial_digitos)

    # Ponto único de substituição: se IA_PROVEDOR estiver configurado no futuro,
    # aqui entraria a chamada à API externa (OpenAI/Anthropic/Gemini) em vez do motor local.
    resultado = analisar_golpe_local(
        texto_mensagem, numero_suspeito, pediu_pagamento, numero_oficial_bate
    )

    # registra como tentativa suspeita quando o risco é relevante e há processo identificado
    if processo and resultado['pontuacao'] >= 45:
        db.session.add(TentativaContato(
            processo_id=processo.id,
            numero_suspeito=numero_suspeito,
            canal=canal,
            descricao=f"[IA Anti-Golpe — risco {resultado['risco']}] {texto_mensagem[:400]}",
            confirmado_golpe=(resultado['pontuacao'] >= 70)
        ))
        db.session.commit()

    return jsonify(resultado)


# ──────────────────────────────────────────────
# RELATÓRIOS EM PDF (Sprint 3) — reportlab, compatível com Windows
# ──────────────────────────────────────────────

_ESTILOS_PDF = getSampleStyleSheet()
_ESTILO_TITULO = ParagraphStyle('TituloAdvogo', parent=_ESTILOS_PDF['Title'], textColor=colors.HexColor('#0a1f3d'), fontSize=18, spaceAfter=2)
_ESTILO_SUBTITULO = ParagraphStyle('SubtituloAdvogo', parent=_ESTILOS_PDF['Normal'], textColor=colors.HexColor('#b9923f'), fontSize=10, spaceAfter=10)
_ESTILO_SECAO = ParagraphStyle('SecaoAdvogo', parent=_ESTILOS_PDF['Heading2'], textColor=colors.HexColor('#15397a'), fontSize=12, spaceBefore=12, spaceAfter=4)
_ESTILO_NORMAL = ParagraphStyle('NormalAdvogo', parent=_ESTILOS_PDF['Normal'], fontSize=9.5, leading=14)
_ESTILO_RODAPE = ParagraphStyle('RodapeAdvogo', parent=_ESTILOS_PDF['Normal'], fontSize=8, textColor=colors.HexColor('#8a93a6'), alignment=TA_CENTER)


def _cabecalho_pdf(story, subtitulo_relatorio):
    story.append(Paragraph('ADVOGO SEGURO', _ESTILO_TITULO))
    story.append(Paragraph('SISTEMA ANTI-GOLPE DO FALSO ADVOGADO', _ESTILO_SUBTITULO))
    story.append(HRFlowable(width='100%', color=colors.HexColor('#b9923f'), thickness=1.2))
    story.append(Spacer(1, 8))
    story.append(Paragraph(subtitulo_relatorio, _ESTILO_SECAO))


def _rodape_pdf(story):
    story.append(Spacer(1, 16))
    story.append(HRFlowable(width='100%', color=colors.HexColor('#e1e6ef'), thickness=0.6))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        f'Documento gerado em {agora_utc().strftime("%d/%m/%Y %H:%M")} (UTC) — '
        f'ADVOGO SEGURO &mdash; SPYNET Tecnologia Forense &amp; Soluções Digitais Ltda.',
        _ESTILO_RODAPE
    ))


def _tabela_chave_valor(pares):
    """Monta uma tabela simples de 'Campo: Valor' para os relatórios."""
    dados = [[Paragraph(f'<b>{k}</b>', _ESTILO_NORMAL), Paragraph(str(v) if v else '—', _ESTILO_NORMAL)] for k, v in pares]
    tabela = Table(dados, colWidths=[55 * mm, 105 * mm])
    tabela.setStyle(TableStyle([
        ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#e1e6ef')),
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f4f6fb')),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
    ]))
    return tabela


def _pdf_response(story, nome_arquivo):
    buffer = io_module.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=18 * mm, bottomMargin=16 * mm,
                             leftMargin=18 * mm, rightMargin=18 * mm)
    doc.build(story)
    buffer.seek(0)
    return Response(
        buffer.read(),
        mimetype='application/pdf',
        headers={'Content-Disposition': f'inline; filename="{nome_arquivo}"'}
    )


@app.route('/api/escritorio/relatorio/contato-seguro/<int:contato_id>/pdf', methods=['GET'])
@login_escritorio_obrigatorio
def relatorio_contato_seguro_pdf(contato_id):
    contato = ContatoSeguro.query.filter_by(id=contato_id, escritorio_id=request.escritorio.id).first()
    if not contato:
        return jsonify({'erro': 'Contato seguro não encontrado.'}), 404

    story = []
    _cabecalho_pdf(story, 'Relatório de Contato Seguro (CCA)')
    story.append(_tabela_chave_valor([
        ('Código CCA', contato.codigo_cca),
        ('Escritório', contato.escritorio.nome),
        ('Advogado responsável', contato.advogado.nome if contato.advogado else '—'),
        ('Cliente', contato.cliente.nome if contato.cliente else '—'),
        ('Processo', contato.processo.codigo_unico if contato.processo else '—'),
        ('Canal', LABEL_CANAL.get(contato.canal, contato.canal)),
        ('Status', contato.status_atual().upper()),
        ('Criado em', contato.criado_em.strftime('%d/%m/%Y %H:%M:%S')),
        ('Expira em', contato.expira_em.strftime('%d/%m/%Y %H:%M:%S')),
        ('Usado em', contato.usado_em.strftime('%d/%m/%Y %H:%M:%S') if contato.usado_em else '—'),
        ('Cancelado em', contato.cancelado_em.strftime('%d/%m/%Y %H:%M:%S') if contato.cancelado_em else '—'),
        ('Observação', contato.observacao or '—'),
    ]))
    _rodape_pdf(story)
    return _pdf_response(story, f'contato_seguro_{contato.codigo_cca}.pdf')


@app.route('/api/escritorio/relatorio/tentativa/<int:tentativa_id>/pdf', methods=['GET'])
@login_escritorio_obrigatorio
def relatorio_tentativa_pdf(tentativa_id):
    tentativa = TentativaContato.query.join(Processo).filter(
        TentativaContato.id == tentativa_id, Processo.escritorio_id == request.escritorio.id
    ).first()
    if not tentativa:
        return jsonify({'erro': 'Tentativa suspeita não encontrada.'}), 404

    processo = tentativa.processo
    story = []
    _cabecalho_pdf(story, 'Relatório de Tentativa Suspeita')
    story.append(_tabela_chave_valor([
        ('Escritório', processo.escritorio.nome),
        ('Advogado responsável', processo.advogado.nome if processo.advogado else '—'),
        ('Cliente', processo.cliente.nome if processo.cliente else '—'),
        ('Processo (código interno)', processo.codigo_unico),
        ('Nº do processo', processo.numero_processo or '—'),
        ('Canal', LABEL_CANAL.get(tentativa.canal, tentativa.canal)),
        ('Número suspeito', tentativa.numero_suspeito or '—'),
        ('Resultado', 'GOLPE CONFIRMADO' if tentativa.confirmado_golpe else 'Em análise'),
        ('Data/hora', tentativa.criado_em.strftime('%d/%m/%Y %H:%M:%S')),
        ('Descrição/observações', tentativa.descricao or '—'),
    ]))
    _rodape_pdf(story)
    return _pdf_response(story, f'tentativa_suspeita_{tentativa.id}.pdf')


@app.route('/api/escritorio/relatorio/mensal/pdf', methods=['GET'])
@login_escritorio_obrigatorio
def relatorio_mensal_pdf():
    """
    Relatório mensal de verificações: aceita ?mes=MM&ano=AAAA (padrão: mês atual).
    Reúne tentativas suspeitas e CCAs do período para visão consolidada do escritório.
    """
    agora = agora_utc()
    mes = int(request.args.get('mes', agora.month))
    ano = int(request.args.get('ano', agora.year))
    inicio = datetime(ano, mes, 1)
    fim = datetime(ano + 1, 1, 1) if mes == 12 else datetime(ano, mes + 1, 1)

    tentativas = TentativaContato.query.join(Processo).options(
        joinedload(TentativaContato.processo).joinedload(Processo.cliente)
    ).filter(
        Processo.escritorio_id == request.escritorio.id,
        TentativaContato.criado_em >= inicio, TentativaContato.criado_em < fim
    ).order_by(TentativaContato.criado_em.asc()).all()
    ccas = ContatoSeguro.query.filter(
        ContatoSeguro.escritorio_id == request.escritorio.id,
        ContatoSeguro.criado_em >= inicio, ContatoSeguro.criado_em < fim
    ).order_by(ContatoSeguro.criado_em.asc()).all()

    story = []
    _cabecalho_pdf(story, f'Relatório Mensal — {mes:02d}/{ano}')
    story.append(_tabela_chave_valor([
        ('Escritório', request.escritorio.nome),
        ('Período', f'{inicio.strftime("%d/%m/%Y")} a {(fim - timedelta(days=1)).strftime("%d/%m/%Y")}'),
        ('Total de Contatos Seguros (CCA) iniciados', len(ccas)),
        ('Total de tentativas suspeitas registradas', len(tentativas)),
        ('Tentativas com golpe confirmado', sum(1 for t in tentativas if t.confirmado_golpe)),
    ]))

    if tentativas:
        story.append(Spacer(1, 10))
        story.append(Paragraph('Detalhamento das tentativas suspeitas', _ESTILO_SECAO))
        linhas = [['Data', 'Cliente', 'Canal', 'Confirmado golpe?']]
        for t in tentativas:
            linhas.append([
                t.criado_em.strftime('%d/%m %H:%M'),
                t.processo.cliente.nome if t.processo and t.processo.cliente else '—',
                LABEL_CANAL.get(t.canal, t.canal or '—'),
                'Sim' if t.confirmado_golpe else 'Não'
            ])
        tabela = Table(linhas, colWidths=[28 * mm, 55 * mm, 35 * mm, 32 * mm])
        tabela.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0a1f3d')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#e1e6ef')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f4f6fb')]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(tabela)

    _rodape_pdf(story)
    return _pdf_response(story, f'relatorio_mensal_{mes:02d}_{ano}.pdf')


@app.route('/api/escritorio/relatorio/processo/<int:processo_id>/pdf', methods=['GET'])
@login_escritorio_obrigatorio
def relatorio_processo_pdf(processo_id):
    """Relatório consolidado por cliente/processo (4º tipo de relatório do briefing)."""
    processo = Processo.query.filter_by(id=processo_id, escritorio_id=request.escritorio.id).first()
    if not processo:
        return jsonify({'erro': 'Processo não encontrado.'}), 404

    tentativas = TentativaContato.query.filter_by(processo_id=processo.id).order_by(TentativaContato.criado_em.asc()).all()
    ccas = ContatoSeguro.query.filter_by(processo_id=processo.id).order_by(ContatoSeguro.criado_em.asc()).all()

    story = []
    _cabecalho_pdf(story, 'Relatório por Cliente / Processo')
    story.append(_tabela_chave_valor([
        ('Escritório', processo.escritorio.nome),
        ('Cliente', processo.cliente.nome if processo.cliente else '—'),
        ('Advogado responsável', processo.advogado.nome if processo.advogado else '—'),
        ('Processo (código interno)', processo.codigo_unico),
        ('Nº do processo', processo.numero_processo or '—'),
        ('Status do processo', processo.status.upper()),
        ('Descrição', processo.descricao or '—'),
        ('Criado em', processo.criado_em.strftime('%d/%m/%Y')),
        ('Total de Contatos Seguros (CCA)', len(ccas)),
        ('Total de tentativas suspeitas', len(tentativas)),
    ]))

    if ccas:
        story.append(Spacer(1, 10))
        story.append(Paragraph('Histórico de Contatos Seguros (CCA)', _ESTILO_SECAO))
        linhas = [['Código', 'Canal', 'Status', 'Criado em']]
        for cca in ccas:
            linhas.append([cca.codigo_cca, LABEL_CANAL.get(cca.canal, cca.canal), cca.status_atual().upper(), cca.criado_em.strftime('%d/%m %H:%M')])
        tabela = Table(linhas, colWidths=[35 * mm, 35 * mm, 35 * mm, 45 * mm])
        tabela.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0a1f3d')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#e1e6ef')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f4f6fb')]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(tabela)

    if tentativas:
        story.append(Spacer(1, 10))
        story.append(Paragraph('Histórico de tentativas suspeitas', _ESTILO_SECAO))
        linhas = [['Data', 'Canal', 'Número suspeito', 'Golpe confirmado?']]
        for t in tentativas:
            linhas.append([
                t.criado_em.strftime('%d/%m %H:%M'),
                LABEL_CANAL.get(t.canal, t.canal or '—'),
                t.numero_suspeito or '—',
                'Sim' if t.confirmado_golpe else 'Não'
            ])
        tabela2 = Table(linhas, colWidths=[28 * mm, 32 * mm, 45 * mm, 35 * mm])
        tabela2.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0a1f3d')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#e1e6ef')),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f4f6fb')]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        story.append(tabela2)

    _rodape_pdf(story)
    return _pdf_response(story, f'relatorio_processo_{processo.codigo_unico}.pdf')


# ──────────────────────────────────────────────
# STRIPE CHECKOUT / ASSINATURAS
# ──────────────────────────────────────────────

def _stripe_configurado():
    return bool(STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET and STRIPE_PRICE_MAP)


def _valor_objeto(objeto, chave, padrao=None):
    if objeto is None:
        return padrao
    if isinstance(objeto, dict):
        return objeto.get(chave, padrao)
    return getattr(objeto, chave, padrao)


def _data_stripe(timestamp):
    if not timestamp:
        return None
    return datetime.fromtimestamp(int(timestamp), tz=timezone.utc).replace(tzinfo=None)


def _url_publica_obrigatoria():
    base = _base_url_publica()
    if not base:
        raise RuntimeError('PUBLIC_BASE_URL precisa estar configurada para o checkout.')
    return base


def _plano_da_assinatura(assinatura):
    metadata = _valor_objeto(assinatura, 'metadata', {}) or {}
    codigo = normalizar_codigo_plano(_valor_objeto(metadata, 'plano'))
    return codigo if codigo in {'profissional', 'escritorio', 'blindagem'} else None


def _subscription_id_da_fatura(fatura):
    legado = _valor_objeto(fatura, 'subscription')
    if legado:
        return str(legado)
    parent = _valor_objeto(fatura, 'parent', {}) or {}
    detalhes = _valor_objeto(parent, 'subscription_details', {}) or {}
    atual = _valor_objeto(detalhes, 'subscription')
    return str(atual) if atual else None


def _escritorio_da_assinatura(assinatura):
    metadata = _valor_objeto(assinatura, 'metadata', {}) or {}
    escritorio_id = _valor_objeto(metadata, 'escritorio_id')
    if escritorio_id:
        try:
            escritorio = db.session.get(Escritorio, int(escritorio_id))
        except (TypeError, ValueError):
            escritorio = None
        if escritorio:
            return escritorio

    assinatura_id = str(_valor_objeto(assinatura, 'id') or '').strip()
    if assinatura_id:
        escritorio = Escritorio.query.filter_by(stripe_subscription_id=assinatura_id).first()
        if escritorio:
            return escritorio

    customer_id = str(_valor_objeto(assinatura, 'customer') or '').strip()
    if customer_id:
        return Escritorio.query.filter_by(stripe_customer_id=customer_id).first()
    return None


def _sincronizar_assinatura_stripe(assinatura):
    escritorio = _escritorio_da_assinatura(assinatura)
    if not escritorio:
        raise LookupError('Escritório da assinatura Stripe não encontrado.')

    assinatura_id = str(_valor_objeto(assinatura, 'id') or '').strip()
    customer_id = str(_valor_objeto(assinatura, 'customer') or '').strip()
    status = str(_valor_objeto(assinatura, 'status') or '').strip().lower()
    plano = _plano_da_assinatura(assinatura) or escritorio.plano_pretendido

    if plano not in {'profissional', 'escritorio', 'blindagem'}:
        raise ValueError('Plano Stripe ausente ou inválido na assinatura.')
    if assinatura_id:
        escritorio.stripe_subscription_id = assinatura_id
    if customer_id:
        escritorio.stripe_customer_id = customer_id
    escritorio.plano_pretendido = plano
    escritorio.assinatura_status = status or 'incomplete'

    if status == 'trialing':
        fim_teste = _data_stripe(_valor_objeto(assinatura, 'trial_end'))
        escritorio.plano = 'trial'
        escritorio.plano_expira = fim_teste or (agora_utc() + timedelta(days=TRIAL_DIAS))
        if not escritorio.trial_utilizado_em:
            escritorio.trial_utilizado_em = agora_utc()
    elif status == 'active':
        escritorio.plano = plano
        escritorio.plano_expira = None
    elif status in {'canceled', 'incomplete_expired', 'unpaid'}:
        escritorio.plano = 'cancelado'
        escritorio.plano_expira = agora_utc()
    elif status in {'past_due', 'paused', 'incomplete'}:
        escritorio.plano = plano
        escritorio.plano_expira = agora_utc()

    db.session.commit()
    return escritorio


def _recuperar_assinatura_stripe(assinatura_id):
    if not assinatura_id:
        raise ValueError('Assinatura Stripe não informada.')
    return stripe.Subscription.retrieve(str(assinatura_id))


@app.route('/api/comercial/checkout', methods=['POST'])
@login_escritorio_obrigatorio
def criar_checkout_stripe():
    if not STRIPE_SECRET_KEY or not STRIPE_PRICE_MAP:
        return jsonify({'erro': 'Contratação online temporariamente indisponível.'}), 503
    if not request.escritorio.email_confirmado():
        return jsonify({'erro': 'Confirme seu e-mail antes da contratação.'}), 403

    data = request.get_json(silent=True) or {}
    plano = normalizar_codigo_plano(data.get('plano') or request.escritorio.plano_pretendido)
    if plano not in {'profissional', 'escritorio', 'blindagem'}:
        return jsonify({'erro': 'Plano indisponível para contratação online.'}), 400
    if request.escritorio.assinatura_status in {'trialing', 'active'}:
        return jsonify({'erro': 'Este escritório já possui uma assinatura em andamento.'}), 409
    tipo_pessoa = (request.escritorio.tipo_pessoa or 'pj').strip().lower()

    if tipo_pessoa == 'pf':
        cpf = _somente_digitos(request.escritorio.cpf)
        if len(cpf) != 11:
            return jsonify({'erro': 'CPF do titular inválido para contratação.'}), 400
        if _outro_escritorio_ja_usou_beneficio_documento(
            'pf', cpf, request.escritorio.id
        ):
            return jsonify({'erro': 'Este CPF já utilizou o benefício de teste.'}), 409
    else:
        cnpj = _somente_digitos(request.escritorio.cnpj)
        if len(cnpj) != 14:
            return jsonify({'erro': 'CNPJ inválido para contratação.'}), 400
        if _outro_escritorio_ja_usou_beneficio_documento(
            'pj', cnpj, request.escritorio.id
        ):
            return jsonify({'erro': 'Este CNPJ já utilizou o benefício de teste.'}), 409

    precos = STRIPE_PRICE_MAP.get(plano)
    if not precos:
        return jsonify({'erro': 'Preço do plano ainda não configurado.'}), 503

    try:
        base = _url_publica_obrigatoria()
        metadata = {'escritorio_id': str(request.escritorio.id), 'plano': plano}
        subscription_data = {'metadata': metadata}
        if not request.escritorio.trial_utilizado_em:
            subscription_data['trial_period_days'] = TRIAL_DIAS
            subscription_data['trial_settings'] = {
                'end_behavior': {'missing_payment_method': 'cancel'}
            }
        line_items = [{'price': precos['mensal'], 'quantity': 1}]
        if not request.escritorio.taxa_implantacao_paga_em:
            line_items.append({'price': precos['implantacao'], 'quantity': 1})

        argumentos = {
            'mode': 'subscription',
            'line_items': line_items,
            'payment_method_collection': 'always',
            'billing_address_collection': 'required',
            'client_reference_id': str(request.escritorio.id),
            'metadata': metadata,
            'subscription_data': subscription_data,
            'success_url': base + '/contratacao/sucesso?session_id={CHECKOUT_SESSION_ID}',
            'cancel_url': base + '/contratacao?cancelado=1',
        }
        if request.escritorio.stripe_customer_id:
            argumentos['customer'] = request.escritorio.stripe_customer_id
        else:
            argumentos['customer_email'] = request.escritorio.email

        sessao = stripe.checkout.Session.create(**argumentos)
    except (stripe.StripeError, RuntimeError, ValueError):
        app.logger.exception('Falha ao criar checkout para escritorio_id=%s.', request.escritorio.id)
        return jsonify({'erro': 'Não foi possível abrir o pagamento. Tente novamente.'}), 502

    request.escritorio.plano_pretendido = plano
    request.escritorio.assinatura_status = 'aguardando_checkout'
    request.escritorio.stripe_checkout_session_id = str(_valor_objeto(sessao, 'id') or '')
    db.session.commit()
    return jsonify({'ok': True, 'checkout_url': _valor_objeto(sessao, 'url')})


@app.route('/api/comercial/checkout/sincronizar', methods=['POST'])
@login_escritorio_obrigatorio
def sincronizar_checkout_stripe():
    if not STRIPE_SECRET_KEY:
        return jsonify({'erro': 'Integração de pagamento indisponível.'}), 503
    data = request.get_json(silent=True) or {}
    session_id = str(data.get('session_id') or '').strip()
    if not session_id or session_id != request.escritorio.stripe_checkout_session_id:
        return jsonify({'erro': 'Sessão de pagamento inválida.'}), 400

    try:
        sessao = stripe.checkout.Session.retrieve(session_id)
        referencia = str(_valor_objeto(sessao, 'client_reference_id') or '')
        if referencia != str(request.escritorio.id):
            return jsonify({'erro': 'Sessão de pagamento não pertence a este escritório.'}), 403
        assinatura_id = _valor_objeto(sessao, 'subscription')
        assinatura = _recuperar_assinatura_stripe(assinatura_id)
        escritorio = _sincronizar_assinatura_stripe(assinatura)
        if _valor_objeto(sessao, 'payment_status') == 'paid' and not escritorio.taxa_implantacao_paga_em:
            escritorio.taxa_implantacao_paga_em = agora_utc()
            db.session.commit()
    except (stripe.StripeError, LookupError, ValueError):
        app.logger.exception('Falha ao sincronizar checkout session_id=%s.', session_id)
        return jsonify({'erro': 'Pagamento recebido; a ativação ainda está sendo processada.'}), 202

    return jsonify({
        'ok': True,
        'assinatura_status': escritorio.assinatura_status,
        'plano': escritorio.plano,
        'proximo': '/escritorio/painel',
    })


@app.route('/api/comercial/status', methods=['GET'])
@login_escritorio_obrigatorio
def status_comercial():
    escritorio = request.escritorio
    return jsonify({
        'email_confirmado': escritorio.email_confirmado(),
        'plano': normalizar_codigo_plano(escritorio.plano),
        'plano_pretendido': escritorio.plano_pretendido,
        'assinatura_status': escritorio.assinatura_status,
        'trial_dias': TRIAL_DIAS,
        'trial_utilizado': bool(escritorio.trial_utilizado_em),
        'taxa_implantacao_paga': bool(escritorio.taxa_implantacao_paga_em),
        'assinatura_gerenciavel': bool(escritorio.stripe_customer_id),
        'plano_ativo': escritorio.plano_ativo(),
    })


@app.route('/api/comercial/portal', methods=['POST'])
@login_escritorio_obrigatorio
def criar_portal_stripe():
    if not STRIPE_SECRET_KEY or not request.escritorio.stripe_customer_id:
        return jsonify({'erro': 'Gerenciamento da assinatura indisponível.'}), 503
    try:
        sessao = stripe.billing_portal.Session.create(
            customer=request.escritorio.stripe_customer_id,
            return_url=_url_publica_obrigatoria() + '/escritorio/configuracoes',
        )
    except (stripe.StripeError, RuntimeError):
        app.logger.exception('Falha ao abrir portal para escritorio_id=%s.', request.escritorio.id)
        return jsonify({'erro': 'Não foi possível abrir o gerenciamento da assinatura.'}), 502
    return jsonify({'ok': True, 'portal_url': _valor_objeto(sessao, 'url')})


@app.route('/webhook/stripe', methods=['POST'])
def webhook_stripe():
    if not STRIPE_WEBHOOK_SECRET or not STRIPE_SECRET_KEY:
        app.logger.error('Webhook Stripe bloqueado: integração não configurada.')
        return jsonify({'erro': 'Webhook indisponível.'}), 503

    assinatura_header = request.headers.get('Stripe-Signature', '')
    try:
        evento = stripe.Webhook.construct_event(
            request.get_data(cache=False), assinatura_header, STRIPE_WEBHOOK_SECRET
        )
    except (ValueError, stripe.SignatureVerificationError):
        return jsonify({'erro': 'Assinatura do webhook inválida.'}), 400

    event_id = str(_valor_objeto(evento, 'id') or '').strip()
    tipo = str(_valor_objeto(evento, 'type') or '').strip()
    dados_evento = _valor_objeto(_valor_objeto(evento, 'data', {}), 'object', {}) or {}
    if not event_id:
        return jsonify({'erro': 'Evento sem identificador.'}), 400
    if EventoWebhook.query.filter_by(provedor='stripe', event_id=event_id).first():
        return jsonify({'ok': True, 'duplicado': True})

    resultado = 'ignorado'
    escritorio = None
    try:
        if tipo == 'checkout.session.completed':
            referencia = _valor_objeto(dados_evento, 'client_reference_id')
            escritorio = db.session.get(Escritorio, int(referencia)) if referencia else None
            if not escritorio:
                raise LookupError('Escritório do checkout não encontrado.')
            escritorio.stripe_checkout_session_id = str(_valor_objeto(dados_evento, 'id') or '')
            escritorio.stripe_customer_id = str(_valor_objeto(dados_evento, 'customer') or '')
            assinatura = _recuperar_assinatura_stripe(_valor_objeto(dados_evento, 'subscription'))
            escritorio = _sincronizar_assinatura_stripe(assinatura)
            if _valor_objeto(dados_evento, 'payment_status') == 'paid' and not escritorio.taxa_implantacao_paga_em:
                escritorio.taxa_implantacao_paga_em = agora_utc()
            resultado = 'checkout_sincronizado'
        elif tipo in {
            'customer.subscription.created',
            'customer.subscription.updated',
            'customer.subscription.deleted',
        }:
            escritorio = _sincronizar_assinatura_stripe(dados_evento)
            resultado = f'assinatura_{escritorio.assinatura_status}'
        elif tipo in {'invoice.paid', 'invoice.payment_failed'}:
            assinatura_id = _subscription_id_da_fatura(dados_evento)
            if assinatura_id:
                escritorio = Escritorio.query.filter_by(
                    stripe_subscription_id=str(assinatura_id)
                ).first()
            if tipo == 'invoice.paid' and assinatura_id:
                escritorio = _sincronizar_assinatura_stripe(
                    _recuperar_assinatura_stripe(assinatura_id)
                )
                resultado = 'fatura_paga'
            elif tipo == 'invoice.payment_failed' and escritorio:
                escritorio.assinatura_status = 'past_due'
                escritorio.plano_expira = agora_utc()
                resultado = 'pagamento_pendente'

        plano = escritorio.plano_pretendido if escritorio else None
        produto_id = (
            escritorio.stripe_subscription_id if escritorio else
            str(_valor_objeto(dados_evento, 'id') or '')
        )
        db.session.add(EventoWebhook(
            provedor='stripe',
            event_id=event_id,
            evento=tipo,
            produto_id=produto_id,
            plano=plano,
            resultado=resultado,
        ))
        db.session.commit()
    except (SQLAlchemyError, stripe.StripeError, LookupError, ValueError, TypeError):
        db.session.rollback()
        app.logger.exception('Falha ao processar webhook Stripe event_id=%s tipo=%s.', event_id, tipo)
        return jsonify({'erro': 'Evento não processado.'}), 500

    return jsonify({'ok': True, 'resultado': resultado})


# ──────────────────────────────────────────────
# WEBHOOK HOTMART (legado preservado)
# ──────────────────────────────────────────────

@app.route('/webhook/hotmart', methods=['POST'])
def webhook_hotmart():
    if not HOTMART_WEBHOOK_TOKEN:
        app.logger.error('Webhook Hotmart bloqueado: HOTMART_WEBHOOK_TOKEN não configurado.')
        return jsonify({'erro': 'Webhook indisponível.'}), 503

    token_recebido = request.headers.get('X-Hotmart-Hottok', '')
    if not token_recebido or not hmac.compare_digest(token_recebido, HOTMART_WEBHOOK_TOKEN):
        return jsonify({'erro': 'Token inválido'}), 403

    payload = request.get_json(silent=True) or {}
    evento = (payload.get('event') or '').strip()
    dados = payload.get('data') or {}
    email_comprador = (((dados.get('buyer') or {}).get('email')) or '').strip().lower()

    eventos_aprovados = {'PURCHASE_COMPLETE', 'PURCHASE_APPROVED'}
    eventos_cancelados = {
        'PURCHASE_REFUNDED',
        'PURCHASE_CANCELED',
        'PURCHASE_CHARGEBACK',
        'SUBSCRIPTION_CANCELLATION',
    }
    if evento not in eventos_aprovados | eventos_cancelados:
        return jsonify({'ok': True, 'ignorado': True, 'motivo': 'evento_sem_efeito'})

    event_id = str(payload.get('id') or '').strip()
    produto_id = str(((dados.get('product') or {}).get('id')) or '').strip()

    if not event_id:
        return jsonify({'erro': 'ID único do evento não encontrado no payload.'}), 400
    if not email_comprador:
        return jsonify({'erro': 'Email não encontrado no payload'}), 400
    if not produto_id:
        return jsonify({'erro': 'Produto não identificado no payload'}), 400

    ja_processado = EventoWebhook.query.filter_by(
        provedor='hotmart', event_id=event_id
    ).first()
    if ja_processado:
        return jsonify({'ok': True, 'duplicado': True})

    codigo_plano = HOTMART_PLAN_MAP.get(produto_id)
    if not codigo_plano:
        # Falha fechada: produto não mapeado nunca concede acesso.
        return jsonify({
            'ok': True,
            'ignorado': True,
            'motivo': 'produto_nao_mapeado',
        }), 202

    escritorio = Escritorio.query.filter_by(email=email_comprador).first()
    if not escritorio:
        return jsonify({'erro': 'Escritório não encontrado para este email'}), 404

    resultado = 'processado'
    if evento in eventos_aprovados:
        agora = agora_utc()
        expira_atual = escritorio.plano_expira
        mesmo_plano = normalizar_codigo_plano(escritorio.plano) == codigo_plano
        base_expiracao = (
            expira_atual
            if mesmo_plano and expira_atual and expira_atual > agora
            else agora
        )
        escritorio.plano = codigo_plano
        escritorio.plano_expira = base_expiracao + timedelta(days=32)
        resultado = 'ativado'
    else:
        # Um cancelamento antigo não derruba um plano diferente comprado depois.
        if normalizar_codigo_plano(escritorio.plano) == codigo_plano:
            escritorio.plano = 'cancelado'
            escritorio.plano_expira = agora_utc()
            resultado = 'cancelado'
        else:
            resultado = 'cancelamento_ignorado_plano_diferente'

    db.session.add(EventoWebhook(
        provedor='hotmart',
        event_id=event_id,
        evento=evento,
        produto_id=produto_id,
        plano=codigo_plano,
        resultado=resultado,
    ))
    db.session.commit()
    return jsonify({'ok': True, 'resultado': resultado, 'plano': codigo_plano})


# ──────────────────────────────────────────────
# ADMIN — segredo somente em cabeçalho, nunca em URL
# ──────────────────────────────────────────────

def _admin_autorizado():
    if not ADMIN_SECRET:
        return False
    recebido = request.headers.get('X-Admin-Secret', '')
    if not recebido:
        auth = request.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            recebido = auth[7:].strip()
    return bool(recebido and hmac.compare_digest(recebido, ADMIN_SECRET))


def _exigir_admin():
    if not ADMIN_SECRET:
        return jsonify({'erro': 'Administração indisponível: ADMIN_SECRET não configurado.'}), 503
    if not _admin_autorizado():
        return jsonify({'erro': 'Não autorizado'}), 403
    return None


@app.route('/api/admin/definir-plano', methods=['POST'])
def admin_definir_plano():
    erro = _exigir_admin()
    if erro:
        return erro

    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    codigo = normalizar_codigo_plano(data.get('codigo'))
    dias = data.get('dias')

    if not email:
        return jsonify({'erro': 'Informe o email do escritório.'}), 400
    if codigo not in PLANOS_ADVOGO_SEGURO:
        return jsonify({'erro': 'Plano inválido.', 'planos_validos': list(PLANOS_ADVOGO_SEGURO.keys())}), 400

    if dias in ('', None):
        dias = None
    else:
        try:
            dias = int(dias)
        except (TypeError, ValueError):
            return jsonify({'erro': 'O campo dias deve ser um número inteiro.'}), 400
        if dias < 1 or dias > 3650:
            return jsonify({'erro': 'Use um prazo entre 1 e 3650 dias.'}), 400

    escritorio = Escritorio.query.filter_by(email=email).first()
    if not escritorio:
        return jsonify({'erro': 'Escritório não encontrado.'}), 404

    escritorio.plano = codigo
    if codigo == 'trial':
        escritorio.plano_expira = agora_utc() + timedelta(days=dias or 7)
    elif dias:
        escritorio.plano_expira = agora_utc() + timedelta(days=dias)
    else:
        escritorio.plano_expira = None
    db.session.commit()

    _, config = escritorio.config_plano()
    return jsonify({
        'ok': True,
        'escritorio': escritorio.nome,
        'email': escritorio.email,
        'plano': codigo,
        'nome_plano': config['nome'],
        'expira_em': escritorio.plano_expira.isoformat() if escritorio.plano_expira else None,
    })


@app.route('/api/admin/ativar-pro', methods=['POST'])
def admin_ativar_pro():
    erro = _exigir_admin()
    if erro:
        return erro
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    if not email:
        return jsonify({'erro': 'Informe o email do escritório.'}), 400
    escritorio = Escritorio.query.filter_by(email=email).first()
    if not escritorio:
        return jsonify({'erro': 'Escritório não encontrado.'}), 404
    escritorio.plano = 'escritorio'
    escritorio.plano_expira = agora_utc() + timedelta(days=365)
    db.session.commit()
    return jsonify({
        'ok': True,
        'email': email,
        'plano': 'escritorio',
        'aviso': 'Endpoint legado mantido por compatibilidade; use /api/admin/definir-plano.',
    })


@app.route('/api/admin/escritorios', methods=['GET'])
def admin_listar():
    erro = _exigir_admin()
    if erro:
        return erro
    lista = Escritorio.query.order_by(Escritorio.criado_em.desc()).all()
    return jsonify([{
        'id': e.id,
        'nome': e.nome,
        'email': e.email,
        'plano': e.plano,
        'processos': len(e.processos),
    } for e in lista])


# ──────────────────────────────────────────────
# HEALTHCHECK
# ──────────────────────────────────────────────

# ──────────────────────────────────────────────
# PÁGINAS — FRONTEND (HTML)
# ──────────────────────────────────────────────

@app.route('/')
def home():
    return render_template(
        'index.html',
        public_base_url=(_base_url_publica() or request.host_url.rstrip('/')),
    )


@app.route('/robots.txt')
def robots_txt():
    base = _base_url_publica() or request.host_url.rstrip('/')
    return Response(
        f'User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /escritorio/\nDisallow: /cliente/\n'
        f'Sitemap: {base}/sitemap.xml\n',
        mimetype='text/plain',
    )


@app.route('/sitemap.xml')
def sitemap_xml():
    base = _base_url_publica() or request.host_url.rstrip('/')
    urls = ('/', '/planos', '/verificar', '/privacidade', '/escritorio/login')
    corpo = ''.join(f'<url><loc>{base}{caminho}</loc></url>' for caminho in urls)
    return Response(
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f'{corpo}</urlset>',
        mimetype='application/xml',
    )


@app.route('/verificar')
def pagina_verificar_publico():
    return render_template('verificar_publico.html')


@app.route('/privacidade')
def pagina_privacidade():
    return render_template(
        'privacidade.html',
        privacy_contact_email=PRIVACY_CONTACT_EMAIL,
        retencao_logs_dias=LGPD_RETENCAO_LOGS_DIAS,
    )


def _catalogo_comercial_publico():
    ordem = ('profissional', 'escritorio', 'blindagem', 'corporativo')
    return [
        {
            'codigo': codigo,
            'nome': PLANOS_ADVOGO_SEGURO[codigo]['nome'],
            'preco_mensal': PLANOS_ADVOGO_SEGURO[codigo]['preco_mensal'],
            'implantacao': PLANOS_ADVOGO_SEGURO[codigo]['implantacao'],
            'limite_advogados': PLANOS_ADVOGO_SEGURO[codigo]['limite_advogados'],
        }
        for codigo in ordem
    ]


@app.route('/api/publico/planos', methods=['GET'])
def api_planos_publicos():
    return jsonify({
        'trial_dias': TRIAL_DIAS,
        'trial_limite_advogados': PLANOS_ADVOGO_SEGURO['trial']['limite_advogados'],
        'planos': _catalogo_comercial_publico(),
    })


@app.route('/planos')
def pagina_planos():
    return render_template(
        'planos.html',
        planos=_catalogo_comercial_publico(),
        trial_dias=TRIAL_DIAS,
        commercial_whatsapp=COMMERCIAL_WHATSAPP,
        commercial_email=COMMERCIAL_EMAIL,
    )


@app.route('/vendas')
def pagina_vendas():
    return render_template('vendas.html')


@app.route('/escritorio/login')
def pagina_escritorio_login():
    return render_template('escritorio_login.html')


@app.route('/escritorio/cadastro')
def pagina_escritorio_cadastro():
    return render_template('escritorio_cadastro.html')


@app.route('/confirmar-email')
def pagina_confirmar_email():
    return render_template('confirmar_email.html')


@app.route('/contratacao')
def pagina_contratacao():
    return render_template('contratacao.html')


@app.route('/contratacao/sucesso')
def pagina_contratacao_sucesso():
    return render_template('contratacao_sucesso.html')


@app.route('/escritorio/painel')
def pagina_escritorio_painel():
    return render_template('painel.html', active='dashboard')


@app.route('/escritorio/dashboard')
def pagina_escritorio_dashboard():
    """Alias de /escritorio/painel — nome usado na especificação do Sprint 3."""
    return render_template('painel.html', active='dashboard')


@app.route('/escritorio/advogados')
def pagina_escritorio_advogados():
    return render_template('advogados.html', active='advogados')


@app.route('/escritorio/processos')
def pagina_escritorio_processos():
    return render_template('processos.html', active='processos')


@app.route('/escritorio/clientes')
def pagina_escritorio_clientes():
    return render_template('clientes.html', active='clientes')


@app.route('/escritorio/tentativas')
def pagina_escritorio_tentativas():
    return render_template('tentativas.html', active='tentativas')


@app.route('/escritorio/contato-seguro')
def pagina_escritorio_contato_seguro():
    return render_template('contato_seguro.html', active='contato_seguro')


@app.route('/escritorio/relatorios')
def pagina_escritorio_relatorios():
    return render_template('relatorios.html', active='relatorios')


@app.route('/escritorio/configuracoes')
def pagina_escritorio_configuracoes():
    return render_template('configuracoes.html', active='configuracoes')


@app.route('/redefinir-senha')
def pagina_redefinir_senha():
    return render_template('redefinir_senha.html')


@app.route('/cliente/login')
def pagina_cliente_login():
    return render_template('cliente_login.html')


@app.route('/cliente/area')
def pagina_cliente_area():
    return render_template('cliente_area.html')


@app.route('/cliente/seguro/<token>')
def pagina_cliente_seguro_token(token):
    """Painel do cliente SEM login/senha — acesso só por link seguro com token (Sprint 3)."""
    return render_template('cliente_seguro_token.html', token=token)


@app.route('/cliente/verificar/<token>')
def pagina_cliente_verificar_token(token):
    """Mesma tela do painel do cliente, com foco na ação de verificar (spec Sprint 3, seção 7)."""
    return render_template('cliente_seguro_token.html', token=token, foco='verificar')


@app.route('/cliente/alerta/<token>')
def pagina_cliente_alerta_token(token):
    """Mesma tela do painel do cliente, com foco na ação de registrar alerta (spec Sprint 3, seção 7)."""
    return render_template('cliente_seguro_token.html', token=token, foco='alerta')


@app.route('/api/health')
def health():
    """Readiness check: serviço só é considerado pronto quando o banco responde."""
    try:
        db.session.execute(text('SELECT 1'))
        return jsonify({
            'status': 'ok',
            'database': 'ok',
            'version': APP_VERSION,
            'timestamp': agora_utc().isoformat(),
        })
    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception('Health check falhou: banco indisponível.')
        return jsonify({
            'status': 'degraded',
            'database': 'unavailable',
            'version': APP_VERSION,
            'timestamp': agora_utc().isoformat(),
        }), 503


@app.route('/api/status')
def api_status():
    return jsonify({
        'app': 'AdvogoSeguro API',
        'status': 'online',
        'spynet': 'Tecnologia Forense & Soluções Digitais'
    })


# ──────────────────────────────────────────────
# INICIALIZAÇÃO
# ──────────────────────────────────────────────

with app.app_context():
    db.create_all()
    _garantir_colunas_novas()
    _garantir_indices_banco()
    _migrar_fotos_legadas_local_para_banco()
    _migrar_ips_legados_para_hash()
    _verificar_integridade_banco_local()
    print('[MIGRACAO] OK!')

if __name__ == '__main__':
    porta = int(os.environ.get('PORT', '5000'))
    debug_local = (
        os.environ.get('FLASK_DEBUG', '0').strip().lower() in {'1', 'true', 'yes', 'on'}
        and not IS_PRODUCTION
    )
    app.run(host='0.0.0.0', port=porta, debug=debug_local)
