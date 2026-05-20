import os, sqlite3
path = r'd:\shieldGuard\shieldguard.db'
print('path', path)
print('exists', os.path.exists(path))
if os.path.exists(path):
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    print(cur.fetchall())
    conn.close()
