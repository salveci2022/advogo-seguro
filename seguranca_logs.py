# -*- coding: utf-8 -*-
"""Mascaramento de tokens em logs (acesso do Gunicorn, erros e logs da aplicação).

Tokens de link seguro, de foto e de redefinição de senha trafegam na URL. Este módulo troca
o valor por *** antes de qualquer gravação, preservando método, caminho, status, horário,
duração e os demais dados operacionais.

Não importa app.py: o Gunicorn carrega este módulo pelo gunicorn.conf.py antes da aplicação.
"""
import logging
import re

MASCARA = '***'

_PADROES = (
    # Links seguros por processo (páginas e API pública).
    re.compile(r'(/cliente/(?:seguro|verificar|alerta)/)[^/?#\s"\']+'),
    re.compile(r'(/api/cliente-publico/[A-Za-z0-9_-]+/)[^/?#\s"\']+'),
    # Token da foto pública do advogado.
    re.compile(r'(/api/publico/foto-advogado/)[^/?#\s"\']+'),
    # Token de redefinição de senha (e equivalentes) na query string.
    re.compile(r'([?&;](?:token|reset_token)=)[^&#\s"\']+', re.IGNORECASE),
)


def mascarar_tokens(texto):
    """Devolve o texto com os tokens conhecidos trocados por ***. Não altera outros tipos."""
    if not isinstance(texto, str) or not texto:
        return texto
    for padrao in _PADROES:
        texto = padrao.sub(r'\1' + MASCARA, texto)
    return texto


class FiltroTokens(logging.Filter):
    """Filtro de logging: mascara a mensagem final e o traceback antes de qualquer handler."""

    def filter(self, record):
        try:
            mensagem = record.getMessage()
        except Exception:  # noqa: BLE001 - mensagem malformada não pode derrubar o log
            return True
        mascarada = mascarar_tokens(mensagem)
        if mascarada != mensagem:
            record.msg = mascarada
            record.args = None
        if record.exc_info and not getattr(record, 'exc_text', None):
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if getattr(record, 'exc_text', None):
            record.exc_text = mascarar_tokens(record.exc_text)
        return True


def instalar_filtro(*loggers):
    """Adiciona um único FiltroTokens a cada logger informado (idempotente)."""
    for logger in loggers:
        if not any(isinstance(f, FiltroTokens) for f in logger.filters):
            logger.addFilter(FiltroTokens())


class MascaraTokensGunicornMixin:
    """Sobrescreve atoms() do logger do Gunicorn: todo valor textual passa pelo mascaramento.

    Cobre %(r)s, %(U)s, %(q)s, {raw_uri}e, {path_info}e, {query_string}e, Referer etc.,
    mantendo status, horário, duração, método e IP.
    """

    def atoms(self, resp, req, environ, request_time):
        atoms = super().atoms(resp, req, environ, request_time)
        return {chave: mascarar_tokens(valor) for chave, valor in atoms.items()}

    def setup(self, cfg):
        super().setup(cfg)
        instalar_filtro(self.error_log, self.access_log)


try:  # Gunicorn só roda em Linux/Unix (depende de fcntl); no Windows o módulo segue importável.
    from gunicorn.glogging import Logger as _LoggerGunicorn
except Exception:  # noqa: BLE001
    _LoggerGunicorn = None

if _LoggerGunicorn is not None:
    class LoggerSemTokens(MascaraTokensGunicornMixin, _LoggerGunicorn):
        """Logger do Gunicorn usado em produção (logger_class em gunicorn.conf.py)."""
