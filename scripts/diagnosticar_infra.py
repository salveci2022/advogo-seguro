# -*- coding: utf-8 -*-
"""Diagnóstico de infraestrutura sem imprimir segredos ou dados pessoais."""
import os
from pathlib import Path
from sqlalchemy import text
import app as appmodule

def status_env(nome):
    return "OK" if bool(os.environ.get(nome, "").strip()) else "AUSENTE"

print("ADVOGO SEGURO — DIAGNÓSTICO DE INFRA")
print("RENDER:", status_env("RENDER"))
print("SECRET_KEY:", status_env("SECRET_KEY"))
print("JWT_SECRET:", status_env("JWT_SECRET"))
print("DATABASE_URL:", status_env("DATABASE_URL"))
print("PUBLIC_BASE_URL:", status_env("PUBLIC_BASE_URL"))
print("SMTP_HOST:", status_env("SMTP_HOST"))
print("HOTMART_WEBHOOK_TOKEN:", status_env("HOTMART_WEBHOOK_TOKEN"))
print("ADMIN_SECRET:", status_env("ADMIN_SECRET"))

with appmodule.app.app_context():
    try:
        appmodule.db.session.execute(text("SELECT 1"))
        print("BANCO_CONEXAO: OK")
        print("BANCO_DIALETO:", appmodule.db.engine.dialect.name)
    except Exception:
        print("BANCO_CONEXAO: FALHA")

uploads = Path(appmodule.UPLOAD_PASTA_ADVOGADOS)
print("UPLOAD_PATH_CONFIGURADO:", str(uploads))
print("UPLOAD_PATH_EXISTE:", "SIM" if uploads.exists() else "NAO")
print("ATENCAO_UPLOAD_RENDER: armazenamento local exige estratégia persistente em produção.")
