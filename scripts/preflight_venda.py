# -*- coding: utf-8 -*-
import json
import os
import sys

def presente(nome):
    return bool(os.environ.get(nome, "").strip())


def habilitado(nome):
    return os.environ.get(nome, "").strip().lower() in {"1", "true", "yes", "on"}

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

if habilitado("COMMERCIAL_FLOW_ENABLED"):
    if os.environ.get("TRIAL_DIAS", "").strip() != "2":
        erros.append("TRIAL_DIAS: deve ser 2")
    for nome in ("STRIPE_SECRET_KEY", "STRIPE_WEBHOOK_SECRET", "STRIPE_PRICE_MAP"):
        if not presente(nome):
            erros.append(f"{nome}: AUSENTE com fluxo comercial habilitado")
    if not presente("SMTP_HOST"):
        erros.append("SMTP_HOST: AUSENTE com confirmação de e-mail habilitada")
    bruto_stripe = os.environ.get("STRIPE_PRICE_MAP", "").strip()
    if bruto_stripe:
        try:
            mapa_stripe = json.loads(bruto_stripe)
            esperados = {"profissional", "escritorio", "blindagem"}
            if not isinstance(mapa_stripe, dict) or set(mapa_stripe) != esperados:
                erros.append("STRIPE_PRICE_MAP: configure exatamente os três planos online")
            elif any(not isinstance(precos, dict) for precos in mapa_stripe.values()):
                erros.append("STRIPE_PRICE_MAP: cada plano deve conter mensal e implantacao")
            elif any(
                not str(precos.get(chave, "")).startswith("price_")
                for precos in mapa_stripe.values()
                for chave in ("mensal", "implantacao")
            ):
                erros.append("STRIPE_PRICE_MAP: IDs devem começar com price_")
        except (json.JSONDecodeError, AttributeError):
            erros.append("STRIPE_PRICE_MAP: JSON inválido")

print("ADVOGO SEGURO — PREFLIGHT DE VENDA")
print("APP_VERSION:", os.environ.get("APP_VERSION", "1.1.0"))
for item in avisos:
    print("AVISO:", item)

if erros:
    for item in erros:
        print("ERRO:", item)
    print("RESULTADO: REPROVADO PARA DEPLOY COMERCIAL")
    sys.exit(1)

print("RESULTADO: APROVADO PARA DEPLOY COMERCIAL")
