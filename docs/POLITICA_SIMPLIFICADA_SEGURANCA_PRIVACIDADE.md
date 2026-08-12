# Política Simplificada de Segurança e Privacidade — ADVOGO SEGURO

> Documento técnico de apoio; revisar e aprovar formalmente antes do uso comercial.

1. Autenticação individual, senha mínima, cookie HttpOnly e proteção CSRF.
2. Segregação por escritório e testes de isolamento.
3. Banco com integridade referencial e PostgreSQL obrigatório em produção.
4. Uploads validados; fotos persistidas no banco.
5. IP bruto não deve ser mantido nos logs persistentes; usar pseudonimização.
6. Exportação autenticada e fila de solicitações de privacidade.
7. Definir retenção documentada antes de executar rotina de limpeza.
8. Incidentes devem ser registrados, avaliados e tratados conforme regulação vigente.
9. Segredos não devem ser versionados.
10. Reavaliar a política em novas integrações, fornecedores ou categorias de dados.
