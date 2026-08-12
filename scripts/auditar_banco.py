# -*- coding: utf-8 -*-
from sqlalchemy import inspect, text
import app as appmodule

db = appmodule.db
with appmodule.app.app_context():
    insp = inspect(db.engine)
    print('DIALETO:', db.engine.dialect.name)
    print('TABELAS:', ', '.join(sorted(insp.get_table_names())))
    if db.engine.dialect.name == 'sqlite':
        print('FOREIGN_KEYS:', db.session.execute(text('PRAGMA foreign_keys')).scalar())
        print('INTEGRITY_CHECK:', db.session.execute(text('PRAGMA integrity_check')).scalar())
        print('ORFAOS:', len(db.session.execute(text('PRAGMA foreign_key_check')).fetchall()))
    if insp.has_table('clientes'):
        duplicados = db.session.execute(text("SELECT COUNT(*) FROM (SELECT telefone FROM clientes WHERE telefone IS NOT NULL GROUP BY telefone HAVING COUNT(*) > 1) AS duplicados")).scalar() or 0
        print('TELEFONES_DUPLICADOS:', duplicados)
    for tabela in sorted(insp.get_table_names()):
        total = db.session.execute(text(f'SELECT COUNT(*) FROM \"{tabela}\"')).scalar()
        print(f'{tabela}: registros={total} indices={len(insp.get_indexes(tabela))}')
