# -*- coding: utf-8 -*-
"""Auditoria local de tamanho dos arquivos, sem ler dados pessoais."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "static"
LIMITE_ALERTA = 500 * 1024

arquivos = [p for p in STATIC.rglob("*") if p.is_file()]
total = sum(p.stat().st_size for p in arquivos)

print(f"ARQUIVOS_STATIC: {len(arquivos)}")
print(f"TAMANHO_STATIC_BYTES: {total}")
print("ARQUIVOS_ACIMA_500KB:")
grandes = sorted(
    (p for p in arquivos if p.stat().st_size > LIMITE_ALERTA),
    key=lambda p: p.stat().st_size,
    reverse=True,
)
if not grandes:
    print("nenhum")
else:
    for p in grandes:
        print(f"- {p.relative_to(ROOT)}: {p.stat().st_size} bytes")
