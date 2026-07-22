# -*- coding: utf-8 -*-
"""
ADVOGO SEGURO — Sistema anti-golpe do falso advogado
SPYNET Tecnologia Forense & Soluções Digitais Ltda

Stack: Flask + SQLAlchemy + PostgreSQL/SQLite + JWT + Hotmart Webhook
Padrão de arquitetura: igual SAE Fácil / NEXORA / PANIFICA PRO 360
"""

import os
import hashlib
import logging
import secrets
import string
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, render_template, Response
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import jwt

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
import io as io_module

# ──────────────────────────────────────────────
# CONFIGURAÇÃO BASE
# ──────────────────────────────────────────────

app = Flask(__name__)

if not app.logger.handlers:
    logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', '*')
if ALLOWED_ORIGINS == '*':
    CORS(app)  # modo aberto (dev). Em produção, defina ALLOWED_ORIGINS no .env
else:
    origins = [o.strip() for o in ALLOWED_ORIGINS.split(',') if o.strip()]
    CORS(app, origins=origins, supports_credentials=True)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'troque-isso-em-producao')
app.config['JWT_SECRET'] = os.environ.get('JWT_SECRET', 'troque-isso-tambem')

IS_PRODUCTION = bool(os.environ.get('RENDER') or os.environ.get('FLASK_ENV') == 'production')
if IS_PRODUCTION and (
    app.config['SECRET_KEY'] == 'troque-isso-em-producao' or
    app.config['JWT_SECRET'] == 'troque-isso-tambem'
):
    raise RuntimeError(
        'SECRET_KEY / JWT_SECRET não configurados em produção! '
        'Defina essas variáveis de ambiente antes de iniciar o servidor.'
    )

DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///advogo_seguro.db')
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

ADMIN_SECRET = os.environ.get('ADMIN_SECRET', 'spynet2026admin')
HOTMART_WEBHOOK_TOKEN = os.environ.get('HOTMART_WEBHOOK_TOKEN', '')
RESET_TOKEN_TTL_MINUTOS = 30
CONTATO_SEGURO_TTL_MINUTOS = int(os.environ.get('CONTATO_SEGURO_TTL_MINUTOS', '10'))


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
        'preco_mensal': 1997.00,
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


def normalizar_codigo_plano(codigo):
    codigo = (codigo or 'trial').strip().lower()
    return PLANOS_LEGADOS.get(codigo, codigo)


def obter_config_plano(codigo):
    codigo_normalizado = normalizar_codigo_plano(codigo)
    return codigo_normalizado, PLANOS_ADVOGO_SEGURO.get(
        codigo_normalizado,
        PLANOS_ADVOGO_SEGURO['trial']
    )

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
    """Retorna (permitido: bool, segundos_restantes: int)"""
    chave = _chave_rate_limit(identificador)
    agora = datetime.utcnow().timestamp()
    tentativas = [t for t in _tentativas_login.get(chave, []) if agora - t < JANELA_BLOQUEIO_SEGUNDOS]
    _tentativas_login[chave] = tentativas
    if len(tentativas) >= MAX_TENTATIVAS:
        restante = int(JANELA_BLOQUEIO_SEGUNDOS - (agora - tentativas[0]))
        return False, max(restante, 1)
    return True, 0


def registrar_tentativa_falha(identificador):
    chave = _chave_rate_limit(identificador)
    _tentativas_login.setdefault(chave, []).append(datetime.utcnow().timestamp())


def limpar_tentativas(identificador):
    chave = _chave_rate_limit(identificador)
    _tentativas_login.pop(chave, None)


# ──────────────────────────────────────────────
# MODELOS
# ──────────────────────────────────────────────

class Escritorio(db.Model):
    __tablename__ = 'escritorios'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(200), nullable=False)
    cnpj = db.Column(db.String(20))
    email = db.Column(db.String(200), unique=True, nullable=False)
    senha_hash = db.Column(db.String(200), nullable=False)
    plano = db.Column(db.String(20), default='trial')  # trial | pro | enterprise
    plano_expira = db.Column(db.DateTime)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)
    reset_token = db.Column(db.String(100))
    reset_token_expira = db.Column(db.DateTime)

    advogados = db.relationship('Advogado', backref='escritorio', lazy=True)
    processos = db.relationship('Processo', backref='escritorio', lazy=True)

    def plano_ativo(self):
        codigo_original = (self.plano or 'trial').strip().lower()
        codigo_normalizado = normalizar_codigo_plano(codigo_original)

        if codigo_normalizado == 'trial':
            return bool(self.plano_expira and self.plano_expira > datetime.utcnow())

        if codigo_normalizado not in PLANOS_ADVOGO_SEGURO:
            return False

        # Contas legadas "pro" e "enterprise" continuam ativas para evitar
        # bloqueio inesperado de clientes já cadastrados.
        if codigo_original in PLANOS_LEGADOS:
            return True

        # Nos planos atuais, data vazia significa contrato sem vencimento
        # automático. Quando houver data, ela precisa estar no futuro.
        return self.plano_expira is None or self.plano_expira > datetime.utcnow()

    def config_plano(self):
        return obter_config_plano(self.plano)

    def limite_advogados(self):
        _, config = self.config_plano()
        return config['limite_advogados']


class Advogado(db.Model):
    __tablename__ = 'advogados'
    id = db.Column(db.Integer, primary_key=True)
    escritorio_id = db.Column(db.Integer, db.ForeignKey('escritorios.id', ondelete='CASCADE'), nullable=False)
    nome = db.Column(db.String(200), nullable=False)
    oab = db.Column(db.String(30))
    telefone_oficial = db.Column(db.String(20), nullable=False)
    foto_url = db.Column(db.String(500))
    ativo = db.Column(db.Boolean, default=True, nullable=False)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)


class Cliente(db.Model):
    __tablename__ = 'clientes'
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(200), nullable=False)
    telefone = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(200))
    senha_hash = db.Column(db.String(200), nullable=False)
    ativo = db.Column(db.Boolean, default=True, nullable=False)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)
    reset_token = db.Column(db.String(100))
    reset_token_expira = db.Column(db.DateTime)

    verificacoes = db.relationship('Verificacao', backref='cliente', lazy=True, cascade='all, delete-orphan')


class Processo(db.Model):
    __tablename__ = 'processos'
    id = db.Column(db.Integer, primary_key=True)
    escritorio_id = db.Column(db.Integer, db.ForeignKey('escritorios.id', ondelete='CASCADE'), nullable=False)
    advogado_id = db.Column(db.Integer, db.ForeignKey('advogados.id', ondelete='CASCADE'), nullable=False)
    cliente_id = db.Column(db.Integer, db.ForeignKey('clientes.id', ondelete='CASCADE'), nullable=False)
    codigo_unico = db.Column(db.String(12), unique=True, nullable=False)
    numero_processo = db.Column(db.String(60))
    descricao = db.Column(db.String(300))
    status = db.Column(db.String(20), default='ativo')  # ativo | arquivado
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)
    token_cliente = db.Column(db.String(100), unique=True)  # link seguro sem login (Sprint 3)

    advogado = db.relationship('Advogado', backref='processos', lazy=True)
    cliente = db.relationship('Cliente', backref='processos', lazy=True)
    tentativas = db.relationship('TentativaContato', backref='processo', lazy=True, cascade='all, delete-orphan')


class Verificacao(db.Model):
    __tablename__ = 'verificacoes'
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('clientes.id', ondelete='CASCADE'), nullable=False)
    numero_consultado = db.Column(db.String(20), nullable=False)
    codigo_consultado = db.Column(db.String(12))
    resultado = db.Column(db.String(20))  # confirmado | nao_encontrado | numero_diferente
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)


class TentativaContato(db.Model):
    __tablename__ = 'tentativas_contato'
    id = db.Column(db.Integer, primary_key=True)
    processo_id = db.Column(db.Integer, db.ForeignKey('processos.id', ondelete='CASCADE'), nullable=False)
    numero_suspeito = db.Column(db.String(20))
    canal = db.Column(db.String(30))  # whatsapp | ligacao | videochamada | email
    descricao = db.Column(db.String(500))
    confirmado_golpe = db.Column(db.Boolean, default=False)
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)


class ContatoSeguro(db.Model):
    """
    'Contato Seguro ADVOGO' / Código de Contato Autorizado (CCA).

    O escritório gera este código ANTES de ligar/mensagear o cliente.
    O cliente nunca recebe nem digita o código — ele apenas consulta,
    em canal separado, se existe um contato autorizado ativo no momento.
    """
    __tablename__ = 'contatos_seguros'
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
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)

    escritorio = db.relationship('Escritorio')
    advogado = db.relationship('Advogado')
    cliente = db.relationship('Cliente')
    processo = db.relationship('Processo')
    logs = db.relationship('ContatoSeguroLog', backref='contato_seguro', lazy=True, cascade='all, delete-orphan')

    def status_atual(self):
        """Recalcula o status no momento da leitura, sem nunca tratar um código vencido como válido."""
        if self.status in ('cancelado', 'expirado'):
            return self.status
        if self.expira_em < datetime.utcnow():
            return 'expirado'
        return self.status


class ContatoSeguroLog(db.Model):
    """Log de auditoria de toda consulta feita pelo cliente (mesmo quando não há contato ativo)."""
    __tablename__ = 'contatos_seguros_logs'
    id = db.Column(db.Integer, primary_key=True)
    cliente_id = db.Column(db.Integer, db.ForeignKey('clientes.id', ondelete='CASCADE'), nullable=False)
    contato_seguro_id = db.Column(db.Integer, db.ForeignKey('contatos_seguros.id', ondelete='CASCADE'), nullable=True)
    encontrado_ativo = db.Column(db.Boolean, default=False)
    ip = db.Column(db.String(60))
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)


class AcessoPublicoLog(db.Model):
    """Auditoria de acesso ao link público do cliente (/cliente/seguro/<token>) — Sprint 3."""
    __tablename__ = 'acessos_publicos_logs'
    id = db.Column(db.Integer, primary_key=True)
    processo_id = db.Column(db.Integer, db.ForeignKey('processos.id', ondelete='CASCADE'), nullable=True)
    acao = db.Column(db.String(40))  # visualizou | verificou | alerta_pix | nao_reconheco
    ip = db.Column(db.String(60))
    criado_em = db.Column(db.DateTime, default=datetime.utcnow)


# ──────────────────────────────────────────────
# MIGRAÇÃO SEGURA (adiciona colunas novas sem apagar dados existentes)
# ──────────────────────────────────────────────
# db.create_all() só cria tabelas que ainda não existem — nunca altera uma
# tabela já existente no Postgres do Render. Como este projeto não usa
# Alembic/Flask-Migrate, novas colunas precisam ser adicionadas manualmente
# aqui, de forma idempotente (só roda se a coluna ainda não existir) e sem
# nenhuma operação destrutiva.

def _garantir_colunas_novas():
    from sqlalchemy import inspect, text

    inspetor = inspect(db.engine)
    colunas_necessarias = [
        ('advogados', 'ativo', 'BOOLEAN NOT NULL DEFAULT TRUE'),
        ('clientes', 'ativo', 'BOOLEAN NOT NULL DEFAULT TRUE'),
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
    return secrets.token_urlsafe(32)


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


def gerar_token(payload, dias=30):
    payload = dict(payload)
    payload['exp'] = datetime.utcnow() + timedelta(days=dias)
    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')


def decodificar_token(token):
    try:
        return jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
    except Exception:
        return None


def login_escritorio_obrigatorio(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        token = auth.replace('Bearer ', '') if auth.startswith('Bearer ') else None
        dados = decodificar_token(token) if token else None
        if not dados or dados.get('tipo') != 'escritorio':
            return jsonify({'erro': 'Não autenticado'}), 401
        escritorio = Escritorio.query.get(dados['id'])
        if not escritorio:
            return jsonify({'erro': 'Escritório não encontrado'}), 404
        request.escritorio = escritorio
        return f(*args, **kwargs)
    return wrapper


def login_cliente_obrigatorio(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        token = auth.replace('Bearer ', '') if auth.startswith('Bearer ') else None
        dados = decodificar_token(token) if token else None
        if not dados or dados.get('tipo') != 'cliente':
            return jsonify({'erro': 'Não autenticado'}), 401
        cliente = Cliente.query.get(dados['id'])
        if not cliente:
            return jsonify({'erro': 'Cliente não encontrado'}), 404
        request.cliente = cliente
        return f(*args, **kwargs)
    return wrapper


@app.route('/api/escritorio/senha', methods=['POST'])
@login_escritorio_obrigatorio
def trocar_senha_escritorio():
    data = request.get_json() or {}
    senha_atual = data.get('senha_atual', '')
    nova_senha = data.get('nova_senha', '')

    if not verificar_senha(request.escritorio.senha_hash, senha_atual):
        return jsonify({'erro': 'Senha atual incorreta'}), 401
    if len(nova_senha) < 6:
        return jsonify({'erro': 'A nova senha deve ter no mínimo 6 caracteres'}), 400

    request.escritorio.senha_hash = hash_senha(nova_senha)
    db.session.commit()
    return jsonify({'ok': True, 'mensagem': 'Senha alterada com sucesso'})


@app.route('/api/escritorio/esqueci-senha', methods=['POST'])
def esqueci_senha_escritorio():
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    escritorio = Escritorio.query.filter_by(email=email).first()

    # Resposta genérica sempre (não revela se o e-mail existe, por segurança)
    resposta = {'ok': True, 'mensagem': 'Se o e-mail existir em nossa base, um link de redefinição foi enviado.'}

    if escritorio:
        escritorio.reset_token = gerar_token_reset()
        escritorio.reset_token_expira = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_TTL_MINUTOS)
        db.session.commit()
        # TODO: integrar envio real por e-mail (SMTP/SendGrid). Por enquanto,
        # o link pode ser obtido pelo admin em /api/admin/reset-links/<secret>/<email>
        link = f"/redefinir-senha?tipo=escritorio&token={escritorio.reset_token}"
        resposta['link_dev'] = link  # ⚠️ remover este campo quando o envio por e-mail estiver configurado

    return jsonify(resposta)


@app.route('/api/escritorio/redefinir-senha', methods=['POST'])
def redefinir_senha_escritorio():
    data = request.get_json() or {}
    token = data.get('token', '')
    nova_senha = data.get('nova_senha', '')

    escritorio = Escritorio.query.filter_by(reset_token=token).first()
    if not escritorio or not escritorio.reset_token_expira or escritorio.reset_token_expira < datetime.utcnow():
        return jsonify({'erro': 'Link de redefinição inválido ou expirado. Solicite um novo.'}), 400
    if len(nova_senha) < 6:
        return jsonify({'erro': 'A nova senha deve ter no mínimo 6 caracteres'}), 400

    escritorio.senha_hash = hash_senha(nova_senha)
    escritorio.reset_token = None
    escritorio.reset_token_expira = None
    db.session.commit()
    return jsonify({'ok': True, 'mensagem': 'Senha redefinida com sucesso. Faça login com a nova senha.'})


@app.route('/api/cliente/senha', methods=['POST'])
@login_cliente_obrigatorio
def trocar_senha_cliente():
    data = request.get_json() or {}
    senha_atual = data.get('senha_atual', '')
    nova_senha = data.get('nova_senha', '')

    if not verificar_senha(request.cliente.senha_hash, senha_atual):
        return jsonify({'erro': 'Senha atual incorreta'}), 401
    if len(nova_senha) < 6:
        return jsonify({'erro': 'A nova senha deve ter no mínimo 6 caracteres'}), 400

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
    telefone = ''.join(filter(str.isdigit, data.get('telefone', '')))
    cliente = Cliente.query.filter_by(telefone=telefone).first()

    resposta = {'ok': True, 'mensagem': 'Se o telefone existir em nossa base, o escritório responsável poderá te enviar um novo acesso.'}
    if cliente:
        cliente.reset_token = gerar_token_reset()
        cliente.reset_token_expira = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_TTL_MINUTOS)
        db.session.commit()

    return jsonify(resposta)


@app.route('/api/cliente/redefinir-senha', methods=['POST'])
def redefinir_senha_cliente():
    data = request.get_json() or {}
    token = data.get('token', '')
    nova_senha = data.get('nova_senha', '')

    cliente = Cliente.query.filter_by(reset_token=token).first()
    if not cliente or not cliente.reset_token_expira or cliente.reset_token_expira < datetime.utcnow():
        return jsonify({'erro': 'Link de redefinição inválido ou expirado. Solicite um novo ao seu escritório.'}), 400
    if len(nova_senha) < 6:
        return jsonify({'erro': 'A nova senha deve ter no mínimo 6 caracteres'}), 400

    cliente.senha_hash = hash_senha(nova_senha)
    cliente.reset_token = None
    cliente.reset_token_expira = None
    db.session.commit()
    return jsonify({'ok': True, 'mensagem': 'Senha redefinida com sucesso. Faça login com a nova senha.'})


@app.route('/api/escritorio/cliente/<int:cliente_id>/link-reset', methods=['GET'])
@login_escritorio_obrigatorio
def gerar_link_reset_cliente(cliente_id):
    """Permite ao escritório gerar/copiar um link de redefinição para reenviar ao cliente por WhatsApp."""
    processo = Processo.query.filter_by(cliente_id=cliente_id, escritorio_id=request.escritorio.id).first()
    if not processo:
        return jsonify({'erro': 'Cliente não encontrado neste escritório'}), 404

    cliente = processo.cliente
    cliente.reset_token = gerar_token_reset()
    cliente.reset_token_expira = datetime.utcnow() + timedelta(minutes=RESET_TOKEN_TTL_MINUTOS)
    db.session.commit()

    return jsonify({'link': f"/redefinir-senha?tipo=cliente&token={cliente.reset_token}", 'cliente_nome': cliente.nome})


# ──────────────────────────────────────────────
# ROTAS — ESCRITÓRIO (B2B)
# ──────────────────────────────────────────────

@app.route('/api/escritorio/registro', methods=['POST'])
def registro_escritorio():
    data = request.get_json() or {}
    nome = data.get('nome', '').strip()
    email = data.get('email', '').strip().lower()
    senha = data.get('senha', '')
    cnpj = data.get('cnpj', '').strip()

    if not nome or not email or len(senha) < 6:
        return jsonify({'erro': 'Preencha nome, email e senha (mín. 6 caracteres)'}), 400

    if Escritorio.query.filter_by(email=email).first():
        return jsonify({'erro': 'Email já cadastrado'}), 409

    escritorio = Escritorio(
        nome=nome, email=email, cnpj=cnpj,
        senha_hash=hash_senha(senha),
        plano='trial',
        plano_expira=datetime.utcnow() + timedelta(days=7)
    )
    db.session.add(escritorio)
    db.session.commit()

    token = gerar_token({'id': escritorio.id, 'tipo': 'escritorio'})
    return jsonify({
        'token': token, 'nome': escritorio.nome,
        'plano': escritorio.plano, 'plano_ativo': escritorio.plano_ativo()
    })


@app.route('/api/escritorio/login', methods=['POST'])
def login_escritorio():
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    senha = data.get('senha', '')

    permitido, espera = verificar_rate_limit(email)
    if not permitido:
        return jsonify({'erro': f'Muitas tentativas de login. Tente novamente em {espera} segundos.'}), 429

    escritorio = Escritorio.query.filter_by(email=email).first()
    if not escritorio or not verificar_senha(escritorio.senha_hash, senha):
        registrar_tentativa_falha(email)
        return jsonify({'erro': 'Email ou senha incorretos'}), 401

    limpar_tentativas(email)
    # upgrade silencioso de hash legado (sha256) para PBKDF2
    if len(escritorio.senha_hash) == 64 and ':' not in escritorio.senha_hash:
        escritorio.senha_hash = hash_senha(senha)
        db.session.commit()

    token = gerar_token({'id': escritorio.id, 'tipo': 'escritorio'})
    return jsonify({
        'token': token, 'nome': escritorio.nome,
        'plano': escritorio.plano, 'plano_ativo': escritorio.plano_ativo()
    })


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
        nome = data.get('nome', '').strip()
        telefone = data.get('telefone_oficial', '').strip()
        if not nome or not telefone:
            return jsonify({'erro': 'Informe o nome e o telefone oficial do advogado.'}), 400

        adv = Advogado(
            escritorio_id=request.escritorio.id,
            nome=nome,
            oab=data.get('oab', '').strip(),
            telefone_oficial=telefone,
            foto_url=data.get('foto_url', '')
        )
        db.session.add(adv)
        db.session.commit()
        return jsonify({'id': adv.id, 'nome': adv.nome})

    lista = Advogado.query.filter_by(escritorio_id=request.escritorio.id).all()
    return jsonify([{
        'id': a.id, 'nome': a.nome, 'oab': a.oab,
        'telefone_oficial': a.telefone_oficial, 'foto_url': a.foto_url,
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
    adv.nome = data.get('nome', adv.nome).strip()
    adv.oab = data.get('oab', adv.oab)
    adv.telefone_oficial = data.get('telefone_oficial', adv.telefone_oficial).strip()
    adv.foto_url = data.get('foto_url', adv.foto_url)
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


@app.route('/api/escritorio/advogados/<int:advogado_id>/foto', methods=['POST'])
@login_escritorio_obrigatorio
def upload_foto_advogado(advogado_id):
    """Upload local de foto do advogado (Sprint 3) — alternativa ao campo foto_url."""
    adv = Advogado.query.filter_by(id=advogado_id, escritorio_id=request.escritorio.id).first()
    if not adv:
        return jsonify({'erro': 'Advogado não encontrado'}), 404

    arquivo = request.files.get('foto')
    if not arquivo or arquivo.filename == '':
        return jsonify({'erro': 'Nenhum arquivo enviado.'}), 400

    if not _extensao_permitida(arquivo.filename):
        return jsonify({'erro': 'Formato não permitido. Use jpg, jpeg, png ou webp.'}), 400

    # nome de arquivo protegido: nunca usa o nome original do usuário
    extensao = arquivo.filename.rsplit('.', 1)[1].lower()
    nome_seguro = secure_filename(f'advogado_{adv.id}_{secrets.token_hex(8)}.{extensao}')
    caminho_completo = os.path.join(UPLOAD_PASTA_ADVOGADOS, nome_seguro)

    arquivo.save(caminho_completo)

    # remove a foto antiga enviada por upload anterior, se existir, para não acumular lixo
    if adv.foto_url and adv.foto_url.startswith('/static/uploads/advogados/'):
        caminho_antigo = os.path.join(app.root_path, adv.foto_url.lstrip('/'))
        if os.path.exists(caminho_antigo):
            try:
                os.remove(caminho_antigo)
            except OSError:
                pass

    adv.foto_url = f'/static/uploads/advogados/{nome_seguro}'
    db.session.commit()
    return jsonify({'ok': True, 'foto_url': adv.foto_url})


@app.route('/api/escritorio/processos', methods=['GET', 'POST'])
@login_escritorio_obrigatorio
def processos():
    if not request.escritorio.plano_ativo():
        return jsonify({'erro': 'Plano inativo. Assine para continuar.', 'limite': True}), 403

    if request.method == 'POST':
        data = request.get_json() or {}

        telefone_normalizado = ''.join(filter(str.isdigit, data.get('cliente_telefone', '')))
        cliente = Cliente.query.filter_by(telefone=telefone_normalizado).first()
        senha_temp = None
        if not cliente:
            senha_temp = secrets.token_hex(4)
            cliente = Cliente(
                nome=data.get('cliente_nome', '').strip(),
                telefone=telefone_normalizado,
                email=data.get('cliente_email', '').strip(),
                senha_hash=hash_senha(senha_temp)
            )
            db.session.add(cliente)
            db.session.flush()

        processo = Processo(
            escritorio_id=request.escritorio.id,
            advogado_id=data.get('advogado_id'),
            cliente_id=cliente.id,
            codigo_unico=gerar_codigo_unico(),
            token_cliente=secrets.token_urlsafe(28),
            numero_processo=data.get('numero_processo', '').strip(),
            descricao=data.get('descricao', '').strip()
        )
        db.session.add(processo)
        db.session.commit()

        return jsonify({
            'id': processo.id,
            'codigo_unico': processo.codigo_unico,
            'cliente_id': cliente.id,
            'cliente_nome': cliente.nome,
            'senha_temporaria': senha_temp,
            'link_cliente_seguro': f'/cliente/seguro/{processo.token_cliente}'
        })

    lista = Processo.query.filter_by(escritorio_id=request.escritorio.id).order_by(Processo.criado_em.desc()).all()
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
        processo.numero_processo = data['numero_processo'].strip()
    if 'descricao' in data:
        processo.descricao = data['descricao'].strip()
    if 'advogado_id' in data and data['advogado_id']:
        processo.advogado_id = data['advogado_id']
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
    processos_ids = [p.id for p in Processo.query.filter_by(escritorio_id=request.escritorio.id).all()]
    tentativas = TentativaContato.query.filter(
        TentativaContato.processo_id.in_(processos_ids)
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
    tentativa = TentativaContato.query.get(tentativa_id)
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

def _serializar_cliente(cliente, escritorio_id):
    processos_escritorio = [p for p in cliente.processos if p.escritorio_id == escritorio_id]
    return {
        'id': cliente.id,
        'nome': cliente.nome,
        'telefone': cliente.telefone,
        'email': cliente.email,
        'ativo': cliente.ativo,
        'processos_count': len(processos_escritorio),
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
    return Cliente.query.get(cliente_id)


@app.route('/api/escritorio/clientes', methods=['GET'])
@login_escritorio_obrigatorio
def listar_clientes():
    lista = _clientes_do_escritorio_query(request.escritorio.id).order_by(Cliente.nome.asc()).all()
    return jsonify([_serializar_cliente(c, request.escritorio.id) for c in lista])


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

    data = request.get_json() or {}
    if 'nome' in data and data['nome'].strip():
        cliente.nome = data['nome'].strip()
    if 'telefone' in data and data['telefone'].strip():
        cliente.telefone = ''.join(filter(str.isdigit, data['telefone']))
    if 'email' in data:
        cliente.email = data['email'].strip()
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
    cliente.ativo = False
    db.session.commit()
    return jsonify({'ok': True, 'ativo': cliente.ativo})


@app.route('/api/escritorio/clientes/<int:cliente_id>/reativar', methods=['POST'])
@login_escritorio_obrigatorio
def reativar_cliente(cliente_id):
    cliente = _cliente_do_escritorio_ou_404(cliente_id, request.escritorio.id)
    if not cliente:
        return jsonify({'erro': 'Cliente não encontrado neste escritório.'}), 404
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
    antigos_ativos = ContatoSeguro.query.filter_by(
        escritorio_id=request.escritorio.id, advogado_id=advogado.id, cliente_id=cliente.id, status='ativo'
    ).all()
    for antigo in antigos_ativos:
        antigo.status = 'cancelado'
        antigo.cancelado_em = datetime.utcnow()

    contato = ContatoSeguro(
        escritorio_id=request.escritorio.id,
        advogado_id=advogado.id,
        cliente_id=cliente.id,
        processo_id=processo.id if processo else None,
        codigo_cca=gerar_codigo_cca(),
        canal=canal,
        status='ativo',
        observacao=observacao,
        expira_em=datetime.utcnow() + timedelta(minutes=CONTATO_SEGURO_TTL_MINUTOS)
    )
    db.session.add(contato)
    db.session.commit()

    return jsonify(_serializar_cca_escritorio(contato))


@app.route('/api/escritorio/contato-seguro/listar', methods=['GET'])
@login_escritorio_obrigatorio
def listar_contato_seguro():
    lista = ContatoSeguro.query.filter_by(escritorio_id=request.escritorio.id) \
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
    contato.cancelado_em = datetime.utcnow()
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
        antigo.cancelado_em = datetime.utcnow()

    novo = ContatoSeguro(
        escritorio_id=antigo.escritorio_id,
        advogado_id=antigo.advogado_id,
        cliente_id=antigo.cliente_id,
        processo_id=antigo.processo_id,
        codigo_cca=gerar_codigo_cca(),
        canal=antigo.canal,
        status='ativo',
        observacao=antigo.observacao,
        expira_em=datetime.utcnow() + timedelta(minutes=CONTATO_SEGURO_TTL_MINUTOS)
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
    agora = datetime.utcnow()
    pendentes = ContatoSeguro.query.filter_by(escritorio_id=request.escritorio.id, status='ativo') \
        .filter(ContatoSeguro.expira_em < agora).all()
    for c in pendentes:
        c.status = 'expirado'
    db.session.commit()
    return jsonify({'ok': True, 'marcados_como_expirados': len(pendentes)})


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
    telefone = ''.join(filter(str.isdigit, data.get('telefone', '')))
    senha = data.get('senha', '')

    permitido, espera = verificar_rate_limit(telefone)
    if not permitido:
        return jsonify({'erro': f'Muitas tentativas de login. Tente novamente em {espera} segundos.'}), 429

    cliente = Cliente.query.filter_by(telefone=telefone).first()
    if not cliente or not verificar_senha(cliente.senha_hash, senha):
        registrar_tentativa_falha(telefone)
        return jsonify({'erro': 'Telefone ou senha incorretos'}), 401

    limpar_tentativas(telefone)
    if len(cliente.senha_hash) == 64 and ':' not in cliente.senha_hash:
        cliente.senha_hash = hash_senha(senha)
        db.session.commit()

    token = gerar_token({'id': cliente.id, 'tipo': 'cliente'})
    return jsonify({'token': token, 'nome': cliente.nome})


@app.route('/api/cliente/processos', methods=['GET'])
@login_cliente_obrigatorio
def processos_do_cliente():
    lista = Processo.query.filter_by(cliente_id=request.cliente.id, status='ativo').all()
    return jsonify([{
        'id': p.id, 'codigo_unico': p.codigo_unico, 'numero_processo': p.numero_processo,
        'advogado_nome': p.advogado.nome if p.advogado else None,
        'escritorio_nome': p.escritorio.nome
    } for p in lista])


# ──────────────────────────────────────────────
# CONTATO SEGURO ADVOGO — lado do cliente
# ──────────────────────────────────────────────

def _ip_cliente():
    return request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()


@app.route('/api/cliente/contato-seguro/ativo', methods=['GET'])
@login_cliente_obrigatorio
def contato_seguro_ativo():
    """
    O cliente nunca informa nada aqui — só consulta. Retorna o contato autorizado
    ativo mais recente para ele, se existir, sem nunca aceitar um código vencido.
    """
    agora = datetime.utcnow()
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

    agora = datetime.utcnow()
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
    numero = ''.join(filter(str.isdigit, data.get('numero', '')))
    codigo = data.get('codigo', '').strip().upper()
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
    return request.headers.get('X-Forwarded-For', request.remote_addr or '').split(',')[0].strip()


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

    agora = datetime.utcnow()
    cca_ativo = ContatoSeguro.query.filter_by(processo_id=processo.id, status='ativo') \
        .filter(ContatoSeguro.expira_em > agora).order_by(ContatoSeguro.criado_em.desc()).first()

    advogado = processo.advogado
    return jsonify({
        'valido': True,
        'escritorio_nome': processo.escritorio.nome,
        'advogado_nome': advogado.nome if advogado else None,
        'advogado_oab': advogado.oab if advogado else None,
        'advogado_foto_url': advogado.foto_url if advogado else None,
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

    agora = datetime.utcnow()
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
    data = request.get_json() or {}
    numero = ''.join(filter(str.isdigit, data.get('numero', '')))
    codigo = data.get('codigo', '').strip().upper()
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
        f'Documento gerado em {datetime.utcnow().strftime("%d/%m/%Y %H:%M")} (UTC) — '
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
    agora = datetime.utcnow()
    mes = int(request.args.get('mes', agora.month))
    ano = int(request.args.get('ano', agora.year))
    inicio = datetime(ano, mes, 1)
    fim = datetime(ano + 1, 1, 1) if mes == 12 else datetime(ano, mes + 1, 1)

    processos_ids = [p.id for p in Processo.query.filter_by(escritorio_id=request.escritorio.id).all()]
    tentativas = TentativaContato.query.filter(
        TentativaContato.processo_id.in_(processos_ids),
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
# WEBHOOK HOTMART
# ──────────────────────────────────────────────

@app.route('/webhook/hotmart', methods=['POST'])
def webhook_hotmart():
    data = request.get_json() or {}

    token_recebido = request.headers.get('X-Hotmart-Hottok', '')
    if HOTMART_WEBHOOK_TOKEN and token_recebido != HOTMART_WEBHOOK_TOKEN:
        return jsonify({'erro': 'Token inválido'}), 403

    evento = data.get('event', '')
    email_comprador = data.get('data', {}).get('buyer', {}).get('email', '').strip().lower()

    if not email_comprador:
        return jsonify({'erro': 'Email não encontrado no payload'}), 400

    escritorio = Escritorio.query.filter_by(email=email_comprador).first()
    if not escritorio:
        return jsonify({'erro': 'Escritório não encontrado para este email'}), 404

    if evento in ('PURCHASE_COMPLETE', 'PURCHASE_APPROVED'):
        escritorio.plano = 'pro'
        escritorio.plano_expira = datetime.utcnow() + timedelta(days=32)
    elif evento in ('PURCHASE_REFUNDED', 'PURCHASE_CANCELED', 'PURCHASE_CHARGEBACK', 'SUBSCRIPTION_CANCELLATION'):
        escritorio.plano = 'cancelado'
        escritorio.plano_expira = None

    db.session.commit()
    return jsonify({'ok': True})


# ──────────────────────────────────────────────
# ADMIN
# ──────────────────────────────────────────────

@app.route('/api/admin/definir-plano/<secret>/<email>/<codigo>', methods=['GET', 'POST'])
def admin_definir_plano(secret, email, codigo):
    if secret != ADMIN_SECRET:
        return jsonify({'erro': 'Não autorizado'}), 403

    codigo = normalizar_codigo_plano(codigo)
    if codigo not in PLANOS_ADVOGO_SEGURO:
        return jsonify({
            'erro': 'Plano inválido.',
            'planos_validos': list(PLANOS_ADVOGO_SEGURO.keys())
        }), 400

    escritorio = Escritorio.query.filter_by(email=email.strip().lower()).first()
    if not escritorio:
        return jsonify({'erro': f'Escritório {email} não encontrado'}), 404

    dias_texto = request.args.get('dias', '').strip()
    dias = None
    if dias_texto:
        try:
            dias = int(dias_texto)
        except ValueError:
            return jsonify({'erro': 'O parâmetro dias deve ser um número inteiro.'}), 400
        if dias < 1 or dias > 3650:
            return jsonify({'erro': 'Use um prazo entre 1 e 3650 dias.'}), 400

    escritorio.plano = codigo
    if codigo == 'trial':
        escritorio.plano_expira = datetime.utcnow() + timedelta(days=dias or 7)
    elif dias:
        escritorio.plano_expira = datetime.utcnow() + timedelta(days=dias)
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


@app.route('/api/admin/ativar-pro/<secret>/<email>')
def admin_ativar_pro(secret, email):
    if secret != ADMIN_SECRET:
        return 'Não autorizado', 403
    escritorio = Escritorio.query.filter_by(email=email.strip().lower()).first()
    if not escritorio:
        return f'Escritório {email} não encontrado', 404
    escritorio.plano = 'pro'
    escritorio.plano_expira = datetime.utcnow() + timedelta(days=365)
    db.session.commit()
    return f'PRO ativado para {email}!'


@app.route('/api/admin/listar-escritorios/<secret>')
def admin_listar(secret):
    if secret != ADMIN_SECRET:
        return 'Não autorizado', 403
    lista = Escritorio.query.order_by(Escritorio.criado_em.desc()).all()
    linhas = ''.join(
        f"<tr><td>{e.id}</td><td>{e.nome}</td><td>{e.email}</td>"
        f"<td>{e.plano}</td><td>{len(e.processos)}</td></tr>"
        for e in lista
    )
    return f"""
    <html><body style="font-family:Arial;padding:20px">
    <h2>AdvogoSeguro — Escritórios cadastrados</h2>
    <table border=1 cellpadding=8 style="border-collapse:collapse">
    <tr><th>ID</th><th>Nome</th><th>Email</th><th>Plano</th><th>Processos</th></tr>
    {linhas}
    </table>
    </body></html>
    """


# ──────────────────────────────────────────────
# HEALTHCHECK
# ──────────────────────────────────────────────

# ──────────────────────────────────────────────
# PÁGINAS — FRONTEND (HTML)
# ──────────────────────────────────────────────

@app.route('/')
def home():
    return render_template('index.html')


@app.route('/verificar')
def pagina_verificar_publico():
    return render_template('verificar_publico.html')


@app.route('/vendas')
def pagina_vendas():
    return render_template('vendas.html')


@app.route('/escritorio/login')
def pagina_escritorio_login():
    return render_template('escritorio_login.html')


@app.route('/escritorio/cadastro')
def pagina_escritorio_cadastro():
    return render_template('escritorio_cadastro.html')


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
    return jsonify({'status': 'ok', 'timestamp': datetime.utcnow().isoformat()})


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
    print('[MIGRACAO] OK!')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
