# MATRIZ COMERCIAL — ADVOGO SEGURO

| Código | Plano | Mensalidade | Implantação | Capacidade |
|---|---|---:|---:|---|
| profissional | Proteção Profissional | R$ 179 | R$ 297 | 1 advogado |
| escritorio | Escritório Protegido | R$ 497 | R$ 697 | até 5 advogados |
| blindagem | Blindagem Jurídica | R$ 997 | R$ 1.497 | até 20 advogados |
| corporativo | Corporativo | a partir de R$ 1.597 | sob consulta | acima de 20 |

## Trial
- 2 dias (48 horas), calculados individualmente pelo servidor.
- 1 advogado ativo.
- 1 cliente e 1 processo.
- O teste só começa após confirmação do e-mail, conclusão do checkout e confirmação do pagamento da implantação.
- Após o teste, a mensalidade do plano escolhido é cobrada automaticamente.
- Um único teste por CNPJ.

## Recursos comprovados para comunicação comercial
- cadastro de advogados, clientes e processos;
- canais oficiais;
- verificação pelo cliente;
- Contato Seguro;
- registro de tentativas suspeitas;
- histórico de verificações;
- relatórios PDF;
- controles de segurança e privacidade já auditados.

## Não prometer como recurso pronto sem nova validação
- múltiplos usuários administrativos com perfis/permissões;
- white-label completo;
- integrações personalizadas prontas;
- filiais como módulo próprio;
- funcionalidades que não constem no produto testado.

## Hotmart
A ativação automática exige `HOTMART_PLAN_MAP`.
Produto não mapeado não concede plano.
Eventos repetidos são tratados por ID único para não estender assinatura duas vezes.

## Stripe
- A integração usa Checkout hospedado e webhooks assinados.
- O cartão não é armazenado no ADVOGO SEGURO.
- `STRIPE_PRICE_MAP` relaciona cada plano aos preços mensal e de implantação.
- Eventos repetidos são idempotentes e não estendem o teste.
- Pagamento recusado bloqueia operações sem apagar dados do escritório.
