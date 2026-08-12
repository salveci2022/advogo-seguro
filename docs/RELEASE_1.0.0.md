# ADVOGO SEGURO — RELEASE 1.0.0

A release 1.0.0 consolida as 10 camadas de auditoria: funcional, estabilidade,
UX/UI, segurança, banco, performance, infraestrutura, LGPD, comercial e prontidão para venda.

## Escopo comprovado
Cadastro de escritórios, advogados, clientes e processos; limites por plano; verificação
de contatos; Contato Seguro; tentativas suspeitas; relatórios PDF; área do cliente;
fotos persistentes; controles de autenticação/CSRF; página de planos e privacidade;
Hotmart quando explicitamente configurada.

## Regra de publicação
Não publicar sem backup do PostgreSQL, preflight aprovado, variáveis reais configuradas,
health check `ok` e smoke test pós-deploy aprovado.
