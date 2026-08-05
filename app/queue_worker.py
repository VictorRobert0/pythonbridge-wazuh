"""Fila durável de alertas + worker.

Objetivo: nenhum alerta do Wazuh e perdido se o IRIS ou o Slack estiverem
indisponiveis no instante em que ele chega. A ingestao apenas ENFILEIRA
(persistido em SQLite) e responde rapido; um worker em background processa
com retry exponencial e move para dead-letter apos esgotar as tentativas.

Simples por padrao (SQLite, instancia unica). Para HA/multi-replica, este
modulo e o ponto onde se troca o backend por Postgres/Redis (ver README).
"""

import json
import logging
import sqlite3
import threading
import time

log = logging.getLogger("queue")
_lock = threading.Lock()


class AlertQueue:
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
                CREATE TABLE IF NOT EXISTS alert_queue (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    payload     TEXT NOT NULL,
                    status      TEXT NOT NULL DEFAULT 'pending',
                    attempts    INTEGER NOT NULL DEFAULT 0,
                    next_try    REAL NOT NULL DEFAULT 0,
                    last_error  TEXT,
                    created_at  REAL NOT NULL,
                    updated_at  REAL NOT NULL
                )
                """
            )
            c.execute(
                "CREATE INDEX IF NOT EXISTS idx_q_status_next "
                "ON alert_queue(status, next_try)"
            )

    def enqueue(self, alert):
        now = time.time()
        with _lock, self._conn() as c:
            cur = c.execute(
                "INSERT INTO alert_queue (payload, status, next_try, created_at, updated_at) "
                "VALUES (?, 'pending', 0, ?, ?)",
                (json.dumps(alert)[:1000000], now, now),
            )
            return cur.lastrowid

    def _claim(self):
        """Pega o proximo item pronto (pending e next_try <= agora)."""
        now = time.time()
        with _lock, self._conn() as c:
            row = c.execute(
                "SELECT * FROM alert_queue WHERE status='pending' AND next_try<=? "
                "ORDER BY id LIMIT 1", (now,),
            ).fetchone()
            if not row:
                return None
            # marca como 'processing' para nao pegar de novo
            c.execute(
                "UPDATE alert_queue SET status='processing', updated_at=? WHERE id=?",
                (now, row["id"]),
            )
            return dict(row)

    def _done(self, item_id):
        with _lock, self._conn() as c:
            c.execute("DELETE FROM alert_queue WHERE id=?", (item_id,))

    def _fail(self, item_id, attempts, err, max_attempts, backoff_base):
        now = time.time()
        with _lock, self._conn() as c:
            if attempts >= max_attempts:
                c.execute(
                    "UPDATE alert_queue SET status='dead', last_error=?, updated_at=? WHERE id=?",
                    (str(err)[:1000], now, item_id),
                )
                log.error("Alerta id=%s movido para dead-letter apos %d tentativas: %s",
                          item_id, attempts, str(err)[:200])
            else:
                delay = backoff_base * (2 ** (attempts - 1))
                c.execute(
                    "UPDATE alert_queue SET status='pending', attempts=?, next_try=?, "
                    "last_error=?, updated_at=? WHERE id=?",
                    (attempts, now + delay, str(err)[:1000], now, item_id),
                )
                log.warning("Alerta id=%s falhou (tentativa %d), retry em %ds: %s",
                            item_id, attempts, delay, str(err)[:200])

    def stats(self):
        with _lock, self._conn() as c:
            rows = c.execute(
                "SELECT status, COUNT(*) n FROM alert_queue GROUP BY status"
            ).fetchall()
            return {r["status"]: r["n"] for r in rows}

    def requeue_stuck(self, older_than=300):
        """Reprocessa itens presos em 'processing' (ex.: apos crash/restart)."""
        limite = time.time() - older_than
        with _lock, self._conn() as c:
            n = c.execute(
                "UPDATE alert_queue SET status='pending' "
                "WHERE status='processing' AND updated_at < ?", (limite,)
            ).rowcount
            if n:
                log.warning("Recolocados %d alertas presos em 'processing'.", n)


def run_worker(queue, handler, max_attempts, poll_sec, backoff_base, stop=None):
    """Loop do worker. `handler(alert_dict)` processa; excecao = retry.

    Roda ate `stop` (threading.Event) ser setado; sem stop, roda para sempre.
    """
    log.info("Worker da fila iniciado (max_attempts=%d, poll=%ds).",
             max_attempts, poll_sec)
    queue.requeue_stuck()
    while not (stop and stop.is_set()):
        item = queue._claim()
        if not item:
            time.sleep(poll_sec)
            continue
        try:
            alert = json.loads(item["payload"])
            handler(alert)
            queue._done(item["id"])
        except Exception as e:  # noqa: BLE001 — qualquer falha = retry
            queue._fail(item["id"], item["attempts"] + 1, e,
                        max_attempts, backoff_base)
