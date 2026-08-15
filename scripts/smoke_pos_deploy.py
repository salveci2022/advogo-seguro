# -*- coding: utf-8 -*-
import json
import os
import sys
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

base = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
if not base:
    raise SystemExit("Defina PUBLIC_BASE_URL antes de executar.")

rotas = [
    ("/api/health", 200),
    ("/", 200),
    ("/planos", 200),
    ("/robots.txt", 200),
    ("/sitemap.xml", 200),
    ("/privacidade", 200),
    ("/escritorio/login", 200),
    ("/escritorio/cadastro", 200),
    ("/confirmar-email", 200),
    ("/cliente/login", 200),
]

falhas = []
for rota, esperado in rotas:
    try:
        req = Request(base + rota, headers={"User-Agent": "AdvogoSeguro-Smoke/1.0"})
        with urlopen(req, timeout=20) as resp:
            if resp.status != esperado:
                falhas.append(f"{rota}: HTTP {resp.status}, esperado {esperado}")
            else:
                print(f"OK {rota}: HTTP {resp.status}")
            if rota == "/api/health":
                dados = json.loads(resp.read().decode("utf-8"))
                if dados.get("status") != "ok" or dados.get("database") != "ok":
                    falhas.append("/api/health: banco/serviço não está pronto")
                print("VERSAO:", dados.get("version"))
    except (HTTPError, URLError, TimeoutError) as exc:
        falhas.append(f"{rota}: {exc}")

if falhas:
    print("RESULTADO: FALHA")
    for item in falhas:
        print("ERRO:", item)
    sys.exit(1)

print("RESULTADO: SMOKE TEST APROVADO")
