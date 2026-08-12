# PLANO DE ROLLBACK — ADVOGO SEGURO 1.0.0

1. Interromper novas alterações manuais no banco.
2. Registrar horário e erro.
3. Se a aplicação falhou e o banco está íntegro, voltar ao último deploy estável.
4. Não restaurar banco automaticamente; verificar primeiro se houve corrupção ou migração destrutiva.
5. Antes de qualquer restauração, preservar uma cópia do estado atual.
6. Depois do rollback, testar `/api/health`, login e leitura dos registros.
7. Corrigir a causa em ambiente de teste antes de redeployar.
