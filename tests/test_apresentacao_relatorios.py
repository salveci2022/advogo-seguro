# -*- coding: utf-8 -*-
"""Apresentação dos PDFs (subtítulo e horário de Brasília) e tela de sucesso do pagamento."""
import os
import re
from datetime import datetime, timezone

import app as appmodule

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _textos(story):
    return [item.text for item in story if hasattr(item, 'text')]


def _ler_template(nome):
    with open(os.path.join(RAIZ, 'templates', nome), encoding='utf-8') as arquivo:
        return arquivo.read()


# ── PDF: subtítulo ─────────────────────────────

def test_pdf_usa_subtitulo_novo():
    story = []
    appmodule._cabecalho_pdf(story, 'Relatório de Teste')
    textos = _textos(story)
    assert 'SEGURANÇA E VALIDAÇÃO DA COMUNICAÇÃO JURÍDICA' in textos
    assert 'SISTEMA ANTI-GOLPE DO FALSO ADVOGADO' not in textos
    assert 'ADVOGO SEGURO' in textos
    assert 'Relatório de Teste' in textos


def test_subtitulo_antigo_nao_aparece_em_nenhum_pdf():
    with open(os.path.join(RAIZ, 'app.py'), encoding='utf-8') as arquivo:
        assert 'SISTEMA ANTI-GOLPE DO FALSO ADVOGADO' not in arquivo.read()


# ── PDF: data/hora em America/Sao_Paulo ────────

def test_rodape_pdf_em_horario_de_brasilia(monkeypatch):
    monkeypatch.setattr(appmodule, 'agora_utc', lambda: datetime(2026, 10, 5, 21, 30))
    story = []
    appmodule._rodape_pdf(story)
    rodape = _textos(story)[-1]
    assert 'Documento gerado em 05/10/2026 18:30 — horário de Brasília' in rodape
    assert '(UTC)' not in rodape


def test_data_brasilia_usa_regras_do_fuso_e_nao_deslocamento_fixo():
    # Em jan/2019 vigorava o horário de verão (UTC-2); hoje é UTC-3.
    # Um deslocamento fixo de -3h erraria a primeira conversão.
    assert appmodule._data_brasilia_pdf(datetime(2019, 1, 15, 12, 0)) == '15/01/2019 10:00'
    assert appmodule._data_brasilia_pdf(datetime(2026, 10, 5, 21, 30)) == '05/10/2026 18:30'
    # Virada de dia: 01:15 UTC ainda é o dia anterior em Brasília.
    assert appmodule._data_brasilia_pdf(datetime(2026, 10, 6, 1, 15), '%d/%m/%Y') == '05/10/2026'
    # Datas com tzinfo explícito também são convertidas corretamente.
    com_fuso = datetime(2026, 10, 5, 21, 30, tzinfo=timezone.utc)
    assert appmodule._data_brasilia_pdf(com_fuso) == '05/10/2026 18:30'
    assert str(appmodule.FUSO_BRASILIA) == 'America/Sao_Paulo'


def test_relatorio_mensal_pdf_continua_sendo_gerado(client):
    resp = client.post('/api/escritorio/registro', json={
        'nome': 'Escritório PDF', 'email': 'pdf@teste.com', 'senha': 'SenhaComercial123!',
    })
    assert resp.status_code == 200, resp.get_json()
    headers = {'Authorization': f"Bearer {resp.get_json()['token']}"}
    with appmodule.app.app_context():
        escritorio = appmodule.Escritorio.query.filter_by(email='pdf@teste.com').first()
        escritorio.plano = 'escritorio'
        escritorio.plano_expira = None
        appmodule.db.session.commit()

    pdf = client.get('/api/escritorio/relatorio/mensal/pdf', headers=headers)
    assert pdf.status_code == 200
    assert pdf.mimetype == 'application/pdf'
    assert pdf.data.startswith(b'%PDF')


# ── Tela de sucesso após pagamento ─────────────

def test_sucesso_com_assinatura_ativa_sem_mensagem_contraditoria():
    html = _ler_template('contratacao_sucesso.html')
    assert 'Pagamento confirmado. Sua assinatura está ativa e o acesso ao plano já foi liberado.' in html
    assert "STATUS_ASSINATURA_LIBERADA = ['active', 'trialing']" in html
    assert 'data.ok && STATUS_ASSINATURA_LIBERADA.includes(data.assinatura_status)' in html

    # O ramo "ativa" esconde o aviso de liberação futura.
    ramo_ativo = html.split('STATUS_ASSINATURA_LIBERADA.includes(data.assinatura_status)')[1].split('} else {')[0]
    assert "document.getElementById('avisoPendente').hidden = true" in ramo_ativo
    assert 'Sua assinatura está ativa' in ramo_ativo


def test_sucesso_pendente_mantem_mensagem_de_espera():
    html = _ler_template('contratacao_sucesso.html')
    aviso = re.search(r'<p id="avisoPendente"[^>]*>(.*?)</p>', html, re.S)
    assert aviso is not None
    assert 'A assinatura será liberada após a confirmação segura do pagamento pelo provedor.' in aviso.group(1)

    ramo_pendente = html.split('STATUS_ASSINATURA_LIBERADA.includes(data.assinatura_status)')[1].split('} else {')[1]
    assert 'A ativação da assinatura ainda está sendo processada.' in ramo_pendente
    assert 'avisoPendente' not in ramo_pendente
    assert 'Sua assinatura está ativa' not in ramo_pendente


def test_pagina_de_sucesso_continua_disponivel(client):
    resposta = client.get('/contratacao/sucesso')
    assert resposta.status_code == 200
    assert 'id="avisoPendente"' in resposta.get_data(as_text=True)
