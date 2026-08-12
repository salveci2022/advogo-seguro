# -*- coding: utf-8 -*-
import json
import os
import sys

def presente(nome):
    return bool(os.environ.get(nome, "").strip())

erros = []
avisos = []

for nome in (
    "DATABASE_URL", "SECRET_KEY", "JWT_SECRET",
    "ADMIN_SECRET", "PUBLIC_BASE_URL", "PRIVACY_CONTACT_EMAIL"
):
    if not presente(nome):
        erros.append(f"{nome}: AUSENTE")

if not (presente("COMMERCIAL_WHATSAPP") or presente("COMMERCIAL_EMAIL")):
    erros.append("CANAL_COMERCIAL: configure COMMERCIAL_WHATSAPP e/ou COMMERCIAL_EMAIL")

if presente("HOTMART_WEBHOOK_TOKEN"):
    bruto = os.environ.get("HOTMART_PLAN_MAP", "").strip()
    if not bruto:
        erros.append("HOTMART_PLAN_MAP: AUSENTE com webhook Hotmart habilitado")
    else:
        try:
            mapa = json.loads(bruto)
            if not isinstance(mapa, dict) or not mapa:
                erros.append("HOTMART_PLAN_MAP: deve ser objeto JSON não vazio")
        except json.JSONDecodeError:
            erros.append("HOTMART_PLAN_MAP: JSON inválido")
else:
    avisos.append("HOTMART: integração automática não habilitada")

if presente("SMTP_HOST"):
    for nome in ("SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM"):
        if not presente(nome):
            erros.append(f"{nome}: AUSENTE com SMTP_HOST configurado")
else:
    avisos.append("SMTP: recuperação por e-mail não configurada")

print("ADVOGO SEGURO — PREFLIGHT DE VENDA")
print("APP_VERSION:", os.environ.get("APP_VERSION", "1.0.0"))
for item in avisos:
    print("AVISO:", item)

if erros:
    for item in erros:
        print("ERRO:", item)
    print("RESULTADO: REPROVADO PARA DEPLOY COMERCIAL")
    sys.exit(1)

print("RESULTADO: APROVADO PARA DEPLOY COMERCIAL")
