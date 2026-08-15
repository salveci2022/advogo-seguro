# RELEASE 1.1.0 — FLUXO COMERCIAL CONTROLADO

## Resultado
- cadastro comercial separado e compatível com contas antigas;
- confirmação de e-mail por código de 6 dígitos;
- Checkout hospedado da Stripe;
- taxa de implantação no início;
- teste controlado por 2 dias;
- 1 advogado, 1 cliente e 1 processo durante o teste;
- cobrança recorrente após o teste;
- ativação, inadimplência e cancelamento sincronizados por webhook assinado;
- portal Stripe para gestão da assinatura;
- páginas públicas preparadas para indexação com robots e sitemap;
- webhook Hotmart legado preservado.

## Segurança e banco
- migração idempotente: somente adiciona colunas e índices;
- nenhum dado ou tabela existente é removido;
- chaves Stripe ficam exclusivamente em variáveis de ambiente;
- eventos Stripe são registrados com ID único para impedir processamento duplicado;
- acesso é liberado somente a partir do estado confirmado da assinatura.

## Antes do deploy
1. Fazer backup verificável do PostgreSQL.
2. Executar toda a suíte de testes.
3. Configurar Stripe e SMTP primeiro em modo de teste.
4. Validar o webhook no ambiente publicado.
5. Executar `scripts/preflight_venda.py` e `scripts/smoke_pos_deploy.py`.

## Rollback
Se houver falha, voltar ao último deploy estável. As novas colunas são compatíveis e não precisam ser removidas. Não restaurar o banco sem antes preservar e auditar o estado atual.
