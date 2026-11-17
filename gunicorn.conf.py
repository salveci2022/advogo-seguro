# -*- coding: utf-8 -*-
"""Configuração lida automaticamente pelo Gunicorn (padrão: ./gunicorn.conf.py).

Só define o logger que mascara tokens de URL nos logs de acesso e de erro. Todas as demais
opções continuam vindo da linha de comando do Procfile/render.yaml, que tem precedência.
"""
logger_class = 'seguranca_logs.LoggerSemTokens'
