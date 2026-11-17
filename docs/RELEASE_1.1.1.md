# RELEASE 1.1.1 — SEGURANÇA DE LOGS E RETORNO SEGURO

Estado: **preparada localmente, não publicada.** Branch `release/1.1.1-seguranca`, base
`origin/main` (`bf2e26a`). Sem mudanças de banco, Stripe, Hotmart, planos, checkout ou termos.

## Objetivo
Ser publicada **antes** da 1.2.0 e servir de **ponto de retorno seguro**: voltar da 1.2.0 para a
1.1.1 não reabre acessos encerrados e não volta a gravar tokens nos logs.

## Pacote A — tokens fora dos logs
- `seguranca_logs.py` e `gunicorn.conf.py` (`logger_class = 'seguranca_logs.LoggerSemTokens'`):
  o log de acesso do Gunicorn troca o token por `***` em `/cliente/seguro|verificar|alerta/…`,
  `/api/cliente-publico/…/…`, `/api/publico/foto-advogado/…` e `?token=`; preserva IP, horário,
  método, caminho, status e bytes.
- Filtro nos logs da aplicação e do werkzeug (mensagem e traceback).
- SQLAlchemy com `hide_parameters=True`: erros do banco sem valores.

## Pacote B — retorno seguro e cliente desativado
- JWT de **cliente** com os campos `sid` ou `gs` (emitidos só pela 1.2.0) é recusado (401,
  "Sessão encerrada. Faça login novamente."). Tokens convencionais continuam válidos; hoje nenhum
  token em produção tem esses campos, então ninguém é deslogado na publicação da 1.1.1.
- Cliente desativado perde na hora as sessões abertas (antes: até 12 h).
- Link seguro por processo de cliente desativado responde como link inexistente e não grava
  alertas. Verificação pública por código preservada. Reativar restaura.
- Autenticação, login e cookies do **escritório**: inalterados.

## Validação
- Suíte completa: **450 aprovados, 1 ignorado (logger real do Gunicorn, só em Linux), 0 falhas**,
  SQLite em memória, rede bloqueada. Inclui 92 testes específicos de logs, retorno seguro, sessão e
  link de cliente desativado.
- Commits: `37c2e9e` (pacote A), `027f3d4` e `119df0d` (pacote B), sobre `bf2e26a`.
- Rollback real entre versões, só com dados fictícios: tokens emitidos e revogados pela 1.2.0
  foram recusados pela 1.1.1 (401) e o link de cliente desativado respondeu 404; na versão
  `bf2e26a` os mesmos casos respondiam 200.
- Gunicorn 22.0.0 real, com o comando do `Procfile`, em contêiner sem rede: `gunicorn.conf.py`
  carregado automaticamente e token ausente do log (0 ocorrências).

## Compatibilidade
- Nenhuma rota nova ou removida; respostas inalteradas, exceto os bloqueios acima.
- Banco: nenhuma tabela ou coluna nova; `_garantir_colunas_novas` inalterada.
- `requirements.txt`, `Procfile` e `render.yaml` inalterados.

## Publicação (depende de autorização)
1. Backup do PostgreSQL (precaução; não há mudança de banco).
2. Anotar o deploy atual na Render e conferir o Start Command (sem outro `-c`/`--logger-class`).
3. `APP_VERSION=1.1.1`.
4. Publicar; conferir `/api/health`, login do escritório e do cliente e um link seguro de teste.
5. No log da Render: linha de acesso com `/cliente/seguro/***`.
6. Clientes já desativados perdem sessões abertas e o link do processo (comportamento esperado).

## Retorno da própria 1.1.1
Rollback para `bf2e26a` pela Render. Sem efeito no banco; os tokens voltam a aparecer completos
nos logs e os bloqueios de cliente desativado deixam de valer.
