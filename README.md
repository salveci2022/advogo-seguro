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
