"""Persistencia do vinculo entre mensagem do Slack e alerta do IRIS.

Guarda thread_ts <-> alert_id para que respostas na thread virem comentarios
no alerta certo, e para reconstruir a mensagem quando um botao e clicado.
"""

import sqlite3
import threading
import json
import time

_lock = threading.Lock()


class Store:
    def __init__(self, path):
        self.path = path
        self._init()

    def _conn(self):
        c = sqlite3.connect(self.path, timeout=15)
        c.row_factory = sqlite3.Row
        return c

    def _init(self):
        with _lock, self._conn() as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_link (
                    thread_ts   TEXT PRIMARY KEY,
                    channel     TEXT NOT NULL,
                    alert_id    INTEGER NOT NULL,
                    alert_title TEXT,
                    decoder     TEXT,
                    rule_id     TEXT,
                    level       INTEGER,
                    raw_alert   TEXT,
                    created_at  REAL NOT NULL
                )
                """
            )
            c.execute(
                "CREATE INDEX IF NOT EXISTS idx_alert_id ON alert_link(alert_id)"
            )
            # coluna case_id adicionada em migracao (pode nao existir em bases antigas)
            cols = [r[1] for r in c.execute("PRAGMA table_info(alert_link)").fetchall()]
            if "case_id" not in cols:
                c.execute("ALTER TABLE alert_link ADD COLUMN case_id INTEGER")
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_event (
                    key        TEXT PRIMARY KEY,
                    created_at REAL NOT NULL
                )
                """
            )

    # ---------- vinculo alerta <-> mensagem ----------

    def link(self, thread_ts, channel, alert_id, title, decoder, rule_id, level, raw):
        with _lock, self._conn() as c:
            c.execute(
                """INSERT OR REPLACE INTO alert_link
                   (thread_ts, channel, alert_id, alert_title, decoder,
                    rule_id, level, raw_alert, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (thread_ts, channel, int(alert_id), title, decoder,
                 str(rule_id), int(level or 0), json.dumps(raw)[:200000], time.time()),
            )

    def by_thread(self, thread_ts):
        with _lock, self._conn() as c:
            row = c.execute(
                "SELECT * FROM alert_link WHERE thread_ts = ?", (thread_ts,)
            ).fetchone()
            return dict(row) if row else None

    def by_alert(self, alert_id):
        with _lock, self._conn() as c:
            row = c.execute(
                "SELECT * FROM alert_link WHERE alert_id = ? ORDER BY created_at DESC LIMIT 1",
                (int(alert_id),),
            ).fetchone()
            return dict(row) if row else None

    def set_case(self, alert_id, case_id):
        """Registra o case criado a partir do alerta (para anexar evidencias)."""
        with _lock, self._conn() as c:
            c.execute(
                "UPDATE alert_link SET case_id = ? WHERE alert_id = ?",
                (int(case_id), int(alert_id)),
            )

    def get_case(self, alert_id):
        with _lock, self._conn() as c:
            row = c.execute(
                "SELECT case_id FROM alert_link WHERE alert_id = ? AND case_id IS NOT NULL "
                "ORDER BY created_at DESC LIMIT 1",
                (int(alert_id),),
            ).fetchone()
            return row["case_id"] if row and row["case_id"] else None

    # ---------- deduplicacao de eventos do Slack ----------

    def seen(self, key, ttl=3600):
        """True se a chave ja foi processada. Marca como vista."""
        now = time.time()
        with _lock, self._conn() as c:
            c.execute("DELETE FROM seen_event WHERE created_at < ?", (now - ttl,))
            row = c.execute(
                "SELECT 1 FROM seen_event WHERE key = ?", (key,)
            ).fetchone()
            if row:
                return True
            c.execute(
                "INSERT INTO seen_event (key, created_at) VALUES (?,?)", (key, now)
            )
            return False
