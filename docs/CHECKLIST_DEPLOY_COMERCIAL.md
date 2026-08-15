# CHECKLIST DE DEPLOY COMERCIAL — ADVOGO SEGURO 1.1.0

## Fluxo Stripe
- [ ] Criar, em modo de teste, os preços mensal e de implantação dos três planos online.
- [ ] Configurar `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` e `STRIPE_PRICE_MAP` na Render.
- [ ] Manter `COMMERCIAL_FLOW_ENABLED=1` e `TRIAL_DIAS=2`.
- [ ] Configurar o webhook Stripe em `https://SEU-DOMINIO/webhook/stripe`.
- [ ] Habilitar o Portal do Cliente no painel Stripe.
- [ ] Confirmar `PUBLIC_BASE_URL` e todas as variáveis SMTP.
- [ ] Testar cadastro, confirmação de e-mail, implantação, trial de 48 horas, mensalidade, recusa e cancelamento.
- [ ] Somente depois dos testes substituir as chaves de teste pelas chaves de produção.

## Antes
- [ ] Confirmar backup recuperável do PostgreSQL.
- [ ] Registrar commit/tag da release.
- [ ] Conferir DATABASE_URL, SECRET_KEY, JWT_SECRET e ADMIN_SECRET.
- [ ] Definir PUBLIC_BASE_URL e PRIVACY_CONTACT_EMAIL.
- [ ] Definir COMMERCIAL_WHATSAPP e/ou COMMERCIAL_EMAIL.
- [ ] Se usar Hotmart: HOTMART_WEBHOOK_TOKEN + HOTMART_PLAN_MAP.
- [ ] Se usar e-mail: conferir SMTP.
- [ ] Executar `python scripts/preflight_venda.py` e exigir APROVADO.

## Deploy
- [ ] Publicar a release aprovada.
- [ ] Acompanhar build/startup.
- [ ] Confirmar migrações sem erro.
- [ ] Confirmar `/api/health` HTTP 200, banco `ok`, versão 1.1.0.

## Depois
- [ ] Executar `python scripts/smoke_pos_deploy.py`.
- [ ] Conferir `/planos` e `/privacidade`.
- [ ] Fazer login de teste controlado.
- [ ] Conferir logs sem erros repetidos.
- [ ] Registrar data, versão e responsável.
