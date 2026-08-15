# ADVOGO SEGURO API

Sistema anti-golpe do falso advogado — backend Flask.

## Rodar local no Windows

```powershell
cd ADVOGO_SEGURO_API_PRONTO
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Abra:

```text
http://127.0.0.1:5000/api/health
```

## Rotas principais

- `POST /api/escritorio/registro`
- `POST /api/escritorio/login`
- `GET/POST /api/escritorio/advogados`
- `GET/POST /api/escritorio/processos`
- `GET /api/escritorio/tentativas`
- `POST /api/cliente/login`
- `GET /api/cliente/processos`
- `POST /api/cliente/verificar`
- `POST /webhook/hotmart`
- `POST /api/comercial/registro`
- `POST /api/comercial/confirmar-email`
- `POST /api/comercial/checkout`
- `POST /webhook/stripe`

## Deploy Render

Use:

```text
Build Command: pip install -r requirements.txt
Start Command: gunicorn app:app
Python: 3.11.9
```

Configure as variáveis de ambiente no Render:

- `SECRET_KEY`
- `JWT_SECRET`
- `ADMIN_SECRET`
- `HOTMART_WEBHOOK_TOKEN`
- `DATABASE_URL`
- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `STRIPE_PRICE_MAP`

## Fluxo comercial 1.1.0

Novos cadastros confirmam o e-mail, concluem o Checkout da Stripe e recebem teste controlado por 2 dias. A implantação é cobrada no início; a mensalidade recorrente começa após o teste. Contas antigas e o webhook Hotmart permanecem compatíveis.

## Recuperação de senha por e-mail

Para habilitar "Esqueci minha senha" do escritório em produção, configure:

- `PUBLIC_BASE_URL` — URL pública do sistema, sem barra final.
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASSWORD`
- `SMTP_FROM`
- `SMTP_SECURITY` — `tls`, `ssl` ou `none`.

Em produção, se o SMTP não estiver configurado, a rota de recuperação retorna indisponibilidade temporária e nunca expõe o token de redefinição. `link_dev` só é disponibilizado fora de produção.
