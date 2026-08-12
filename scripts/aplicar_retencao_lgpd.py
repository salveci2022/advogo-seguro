# -*- coding: utf-8 -*-
import app as appmodule

dias = appmodule.LGPD_RETENCAO_LOGS_DIAS
if dias <= 0:
    raise SystemExit(
        'RETENÇÃO NÃO EXECUTADA: defina LGPD_RETENCAO_LOGS_DIAS conforme a política aprovada.'
    )

with appmodule.app.app_context():
    resultado = appmodule._aplicar_retencao_logs_privacidade(dias)
    print('RETENÇÃO EXECUTADA')
    print('DIAS:', dias)
    print('CONTATOS_SEGUROS_LOGS_REMOVIDOS:', resultado['contatos_seguros_logs'])
    print('ACESSOS_PUBLICOS_LOGS_REMOVIDOS:', resultado['acessos_publicos_logs'])
