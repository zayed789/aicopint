import os
os.chdir(os.path.dirname(os.path.abspath(__file__)))
from dotenv import load_dotenv
load_dotenv('.env')
from sqlalchemy.engine import make_url
import psycopg2

u    = make_url(os.environ['DATABASE_URL'])
conn = psycopg2.connect(host=u.host, port=u.port or 5432,
                        user=u.username, password=u.password, dbname=u.database)
cur  = conn.cursor()

print('=== TABLES ===')
cur.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
for (t,) in cur.fetchall():
    cur2 = conn.cursor()
    cur2.execute(f'SELECT COUNT(*) FROM "{t}"')
    print(f'  {t:30s}  rows={cur2.fetchone()[0]}')
    cur2.close()

print()
print('=== USERS ===')
cur.execute('SELECT id, username, role, is_active, account_locked, last_login, created_at FROM users ORDER BY created_at')
for r in cur.fetchall():
    print(f'  {r[1]:20s}  role={r[2]:10s}  active={str(r[3]):5s}  locked={str(r[4]):5s}  last_login={str(r[5])[:16] if r[5] else "never":16s}  created={str(r[6])[:10]}')

print()
print('=== AUDIT_LOGS (last 10) ===')
cur.execute('SELECT action, status, ip_address, details, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 10')
for r in cur.fetchall():
    import json as _j
    details = _j.loads(r[3]) if r[3] else {}
    print(f'  {str(r[4])[:19]}  {r[0]:25s}  {r[1]:8s}  ip={r[2]}  {details}')

cur.close()
conn.close()
