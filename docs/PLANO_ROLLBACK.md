# PLANO DE ROLLBACK — ADVOGO SEGURO 1.0.0

1. Interromper novas alterações manuais no banco.
2. Registrar horário e erro.
3. Se a aplicação falhou e o banco está íntegro, voltar ao último deploy estável.
4. Não restaurar banco automaticamente; verificar primeiro se houve corrupção ou migração destrutiva.
5. Antes de qualquer restauração, preservar uma cópia do estado atual.
6. Depois do rollback, testar `/api/health`, login e leitura dos registros.
7. Corrigir a causa em ambiente de teste antes de redeployar.

---

# ROLLBACK — VERSÃO 1.1.1 (segurança de logs e retorno seguro)

> Procedimento documentado; nenhuma restauração foi executada.

- A 1.1.1 não altera o banco: voltar dela para `bf2e26a` é só voltar o deploy pela Render.
- Efeitos de voltar para `bf2e26a`: tokens voltam a aparecer completos nos logs; clientes
  desativados voltam a usar sessões ainda válidas (até 12 h) e o link do processo.

## A 1.1.1 como ponto de retorno da 1.2.0
Ordem planejada: publicar a 1.1.1, estabilizar e só então publicar a 1.2.0. Se for preciso voltar
da 1.2.0, voltar para o deploy da **1.1.1** (não para `bf2e26a`):
- JWTs de cliente emitidos pela 1.2.0 (campos `sid`/`gs`) são recusados: clientes que entraram
  durante a 1.2.0 fazem login de novo; escritórios não são afetados; **não é preciso trocar
  `JWT_SECRET`**.
- Clientes desativados continuam bloqueados (sessões e link do processo).
- Logs continuam sem tokens.
- As tabelas `sessoes_cliente` e `controle_acesso_cliente` ficam no banco e são ignoradas.
- Validado em ensaio com dados fictícios: os quatro casos que respondiam 200 em `bf2e26a`
  responderam 401/404 na 1.1.1.
