"""Configuracao centralizada do SOC Bridge.

Le variaveis de ambiente e, para segredos, tambem o padrao Docker/K8s secrets:
para qualquer chave X, se existir X_FILE apontando para um arquivo, o valor e
lido do arquivo (tem prioridade). Isso permite montar segredos como arquivos em
vez de deixa-los em texto no ambiente.

Uso:
    from config import settings
    settings.SLACK_BOT_TOKEN
"""

import json
import os


def _read(name, default=None, secret=False):
    """Le uma variavel. Se secret e existir <NAME>_FILE, le do arquivo."""
    if secret:
        path = os.getenv(name + "_FILE")
        if path:
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return f.read().strip()
            except OSError as e:
                raise RuntimeError(
                    "Nao consegui ler o segredo {} de {}: {}".format(name, path, e))
    return os.getenv(name, default)


def _bool(name, default=False):
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on", "sim")


def _int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


class Settings:
    def __init__(self):
        # ---- Slack ----
        self.SLACK_BOT_TOKEN = _read("SLACK_BOT_TOKEN", secret=True)
        self.SLACK_APP_TOKEN = _read("SLACK_APP_TOKEN", secret=True)
        self.SLACK_CHANNEL = _read("SLACK_CHANNEL", "#soc-alerts")

        # ---- DFIR-IRIS ----
        self.IRIS_URL_INTERNAL = _read("IRIS_URL_INTERNAL")
        self.IRIS_URL_PUBLIC = _read("IRIS_URL_PUBLIC", self.IRIS_URL_INTERNAL)
        self.IRIS_API_KEY = _read("IRIS_API_KEY", secret=True)
        self.IRIS_CUSTOMER_ID = _int("IRIS_CUSTOMER_ID", 1)
        self.IRIS_VERIFY_TLS = _bool("IRIS_VERIFY_TLS", False)
        # caminho de um bundle de CA para validar o certificado do IRIS
        self.IRIS_CA_BUNDLE = _read("IRIS_CA_BUNDLE")
        self.IRIS_DEFAULT_RESOLUTION = (_read("IRIS_DEFAULT_RESOLUTION", "") or "").strip()

        # ---- Wazuh ----
        self.WAZUH_DASHBOARD_URL = _read("WAZUH_DASHBOARD_URL", "")
        self.WAZUH_WINDOW_MIN = _int("WAZUH_WINDOW_MIN", 30)
        self.WAZUH_DISCOVER_ROUTE = _read("WAZUH_DISCOVER_ROUTE", "data-explorer")
        self.WAZUH_INDEX_PATTERN = _read("WAZUH_INDEX_PATTERN", "wazuh-alerts-*")
        self.DC_AGENTS = _read("DC_AGENTS", "dc01-ad")

        # ---- Sophos Firewall (banir IP) ----
        self.SOPHOS_URL = _read("SOPHOS_URL", "")           # ex: https://172.16.16.16:4444
        self.SOPHOS_USER = _read("SOPHOS_USER", "")
        self.SOPHOS_PASS = _read("SOPHOS_PASS", secret=True)
        self.SOPHOS_BLOCK_GROUP = _read("SOPHOS_BLOCK_GROUP", "SOC_Blocklist")
        self.SOPHOS_VERIFY_TLS = _bool("SOPHOS_VERIFY_TLS", False)
        # feature so liga se URL + credenciais existirem
        self.SOPHOS_ENABLED = bool(self.SOPHOS_URL and self.SOPHOS_USER and self.SOPHOS_PASS)

        # ---- Seguranca da ingestao ----
        # Token compartilhado exigido no POST /wazuh (header X-Bridge-Token ou
        # ?token=). Vazio = sem autenticacao (apenas para lab isolado).
        self.INGEST_TOKEN = _read("INGEST_TOKEN", "", secret=True)

        # ---- Comportamento ----
        self.CLOSE_WITH_MODAL = _bool("CLOSE_WITH_MODAL", True)
        try:
            self.USER_MAP = json.loads(os.getenv("SLACK_IRIS_USER_MAP", "{}"))
        except Exception:
            self.USER_MAP = {}

        # ---- Fila durável / worker ----
        self.QUEUE_MAX_ATTEMPTS = _int("QUEUE_MAX_ATTEMPTS", 6)
        self.QUEUE_POLL_SEC = _int("QUEUE_POLL_SEC", 2)
        self.QUEUE_BACKOFF_BASE_SEC = _int("QUEUE_BACKOFF_BASE_SEC", 5)

        # ---- Infra ----
        self.BRIDGE_PORT = _int("BRIDGE_PORT", 8000)
        self.DB_PATH = _read("DB_PATH", "/data/bridge.db")
        self.LOG_LEVEL = _read("LOG_LEVEL", "INFO")

    def resolve_verify(self):
        """Valor para o parametro verify do requests."""
        if self.IRIS_CA_BUNDLE:
            return self.IRIS_CA_BUNDLE
        return self.IRIS_VERIFY_TLS

    def require(self, *names):
        """Levanta se alguma variavel obrigatoria estiver vazia."""
        faltando = [n for n in names if not getattr(self, n, None)]
        if faltando:
            raise RuntimeError(
                "Config obrigatoria ausente: {}. Preencha no .env ou via *_FILE."
                .format(", ".join(faltando)))


settings = Settings()
