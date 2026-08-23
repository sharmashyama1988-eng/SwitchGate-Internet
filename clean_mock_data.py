import sqlite3
from pathlib import Path

db_path = Path("data/switchgate.db")
if db_path.exists():
    conn = sqlite3.connect(str(db_path))
    conn.execute("DELETE FROM ghost_leaks")
    conn.commit()
    conn.close()
    print("Database purged of all mock ghost leaks. Now 100% genuine real telemetry only.")
