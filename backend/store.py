import contextlib
import os
import threading
from pathlib import Path

import duckdb

LOCK = threading.RLock()
DB_PATH = os.environ.get('DB_PATH', str(Path(__file__).resolve().parents[1] / 'tmp/kc.duckdb'))


@contextlib.contextmanager
def connect(path=None):
    """One process owns DuckDB. Jobs run in that process; worker processes only write Parquet."""
    with LOCK:
        target = str(path or DB_PATH)
        Path(target).parent.mkdir(parents=True, exist_ok=True)
        db = duckdb.connect(target, config={'memory_limit': '2GB', 'threads': 2})
        try:
            db.execute('CREATE TABLE IF NOT EXISTS cache (key VARCHAR PRIMARY KEY, value VARCHAR)')
            db.execute('CREATE TABLE IF NOT EXISTS chunks (run_id VARCHAR, chunk_id VARCHAR, parquet VARCHAR, PRIMARY KEY(run_id,chunk_id))')
            db.execute('CREATE TABLE IF NOT EXISTS incident_paths (incident_id VARCHAR PRIMARY KEY, status VARCHAR, risk INTEGER, path_json VARCHAR)')
            yield db
        finally:
            db.close()


def records(cursor):
    names = [c[0] for c in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]
