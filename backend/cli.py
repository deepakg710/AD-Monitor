"""Local administrative entry point. Passwords are read with getpass, never CLI flags."""
import argparse, getpass, os, sqlite3, sys
from pathlib import Path
from .db import Database, audit
from .security import create_user
from .rules import seed_rules

ROOT=Path(__file__).resolve().parent.parent

def main():
    p=argparse.ArgumentParser(); p.add_argument('--db',default=os.environ.get('ADMONITOR_DB',str(ROOT/'data'/'admonitor.db')))
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('init'); a=sub.add_parser('create-admin'); a.add_argument('--username',required=True)
    backup=sub.add_parser('backup'); backup.add_argument('destination')
    restore=sub.add_parser('restore'); restore.add_argument('source')
    serve=sub.add_parser('serve'); serve.add_argument('--host',default='127.0.0.1'); serve.add_argument('--port',type=int,default=8765); serve.add_argument('--cert'); serve.add_argument('--key')
    args=p.parse_args(); db=Database(args.db)
    if args.command=='restore':
        # Require an absent destination, avoiding replacement of active WAL files.
        if db.path.exists() or db.path.with_name(db.path.name+'-wal').exists(): p.error('Restore requires an absent destination database; stop the app and use --db with a new path')
        source=sqlite3.connect(f'file:{Path(args.source).resolve().as_posix()}?mode=ro',uri=True)
        if source.execute('PRAGMA integrity_check').fetchone()[0]!='ok': p.error('Backup integrity check failed')
        target=sqlite3.connect(db.path); source.backup(target); target.close(); source.close(); print('Database restored. Copy matching models folder separately if needed.'); return
    db.migrate()
    with db.tx() as c: seed_rules(c)
    if args.command=='init': print('Migrations applied. No employee activity or default user credentials created.')
    elif args.command=='create-admin':
        password=getpass.getpass('New local application password (12+ characters): ')
        if password!=getpass.getpass('Repeat password: '): p.error('Passwords do not match')
        with db.tx() as c: create_user(c,args.username,password)
        print('Administrator created.')
    elif args.command=='backup': db.backup(args.destination); print('Consistent SQLite backup created. Also copy the models folder while no model job is running.')
    elif args.command=='serve':
        if args.host not in ('127.0.0.1','localhost','::1') and not (args.cert and args.key): p.error('A LAN listener requires --cert and --key; HTTP is loopback-only')
        import uvicorn
        from .app import make_app
        uvicorn.run(make_app(args.db),host=args.host,port=args.port,ssl_certfile=args.cert,ssl_keyfile=args.key,workers=1,proxy_headers=False,log_level='info',access_log=False)

if __name__=='__main__': main()
