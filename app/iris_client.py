"""Cliente da API do DFIR-IRIS.

Resolve IDs de lookup (status, resolucao, usuarios) por nome na inicializacao,
porque esses IDs variam entre instalacoes do IRIS.
"""

import json
import logging
import threading
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("iris")


class IrisClient:
    def __init__(self, base_url, api_key, verify_ssl=False, customer_id=1):
        self.base = base_url.rstrip("/")
        self.key = api_key
        self.verify = verify_ssl
        self.customer_id = customer_id
        self._lock = threading.Lock()
        self._note_lock = threading.Lock()
        self._status_map = {}      # nome_lower -> id
        self._resolution_map = {}  # nome_lower -> id
        self._users = []           # [{id, name, email, login}]
        self._loaded = False

    # ---------- infra ----------

    def _headers(self):
        return {
            "Content-Type": "application/json",
            "Authorization": "Bearer {}".format(self.key),
        }

    def _get(self, path, **kw):
        r = requests.get(self.base + path, headers=self._headers(),
                         verify=self.verify, timeout=30, **kw)
        r.raise_for_status()
        return r.json()

    def _post(self, path, payload):
        r = requests.post(self.base + path, headers=self._headers(),
                          json=payload, verify=self.verify, timeout=30)
        if r.status_code >= 400:
            # extrai a mensagem util do IRIS (campo "message" ou "data") em vez
            # do "400 Client Error" generico, para o chamador mostrar no Slack
            detalhe = r.text[:500]
            try:
                j = r.json()
                detalhe = j.get("message") or json.dumps(j.get("data") or j)[:500]
            except Exception:
                pass
            log.error("POST %s -> %s: %s", path, r.status_code, r.text[:800])
            raise RuntimeError("IRIS {} — {}".format(r.status_code, detalhe))
        return r.json()

    # ---------- lookups ----------

    def load_lookups(self, force=False):
        """Carrega mapas de status, resolucao e usuarios. Idempotente."""
        with self._lock:
            if self._loaded and not force:
                return
            try:
                data = self._get("/manage/alert-status/list")
                for it in data.get("data", []):
                    self._status_map[it["status_name"].strip().lower()] = it["status_id"]
                log.info("Status carregados: %s", self._status_map)
            except Exception as e:
                log.warning("Falha ao carregar alert-status: %s", e)

            try:
                data = self._get("/manage/alert-resolutions/list")
                for it in data.get("data", []):
                    self._resolution_map[
                        it["resolution_status_name"].strip().lower()
                    ] = it["resolution_status_id"]
                log.info("Resolucoes carregadas: %s", self._resolution_map)
            except Exception as e:
                log.warning("Falha ao carregar alert-resolutions: %s", e)

            try:
                data = self._get("/manage/users/list")
                self._users = [
                    {
                        "id": u.get("user_id"),
                        "name": u.get("user_name"),
                        "login": u.get("user_login"),
                        "email": (u.get("user_email") or "").strip().lower(),
                    }
                    for u in data.get("data", [])
                ]
                log.info("Usuarios IRIS carregados: %d", len(self._users))
            except Exception as e:
                log.warning("Falha ao carregar usuarios: %s", e)

            # So considera carregado quando os mapas criticos vieram populados.
            # Se o IRIS estava indisponivel no boot, deixa _loaded=False para
            # que a proxima chamada tente de novo (evita cair no fallback de
            # uma unica resolucao para sempre).
            self._loaded = bool(self._status_map and self._resolution_map)
            if not self._loaded:
                log.warning(
                    "Lookups incompletos (status=%d, resolucoes=%d) — "
                    "tentara novamente na proxima chamada.",
                    len(self._status_map), len(self._resolution_map),
                )

    def list_case_templates(self):
        """Retorna [(id, nome), ...] dos templates de case do IRIS.

        Defensivo: se o endpoint nao existir nessa versao, retorna lista vazia
        e o modal simplesmente nao mostra o dropdown de templates.
        """
        out = []
        for path in ("/manage/case-templates/list", "/manage/case-template/list"):
            try:
                data = self._get(path)
            except Exception:
                continue
            items = data.get("data")
            if isinstance(items, dict):
                items = items.get("case_templates") or items.get("templates") or []
            for it in items or []:
                tid = it.get("id") or it.get("case_template_id")
                name = (it.get("name") or it.get("case_template_name")
                        or "Template {}".format(tid))
                if tid is not None:
                    out.append((tid, name))
            if out:
                break
        return out

    def status_id(self, *names, default=None):
        """Primeiro nome que existir no mapa. Ex: status_id('closed', 'fechado')."""
        self.load_lookups()
        for n in names:
            v = self._status_map.get(n.strip().lower())
            if v is not None:
                return v
        return default

    def resolution_id(self, *names, default=None):
        self.load_lookups()
        for n in names:
            v = self._resolution_map.get(n.strip().lower())
            if v is not None:
                return v
        return default

    def user_by_email(self, email):
        if not email:
            return None
        self.load_lookups()
        email = email.strip().lower()
        for u in self._users:
            if u["email"] == email:
                return u
        return None

    def user_by_login(self, login):
        if not login:
            return None
        self.load_lookups()
        login = login.strip().lower()
        for u in self._users:
            if (u["login"] or "").lower() == login:
                return u
        return None

    # ---------- alertas ----------

    def create_alert(self, payload):
        payload.setdefault("alert_customer_id", self.customer_id)
        resp = self._post("/alerts/add", payload)
        data = resp.get("data", {})
        return data.get("alert_id"), data

    def update_alert(self, alert_id, payload):
        return self._post("/alerts/update/{}".format(alert_id), payload)

    def get_alert(self, alert_id):
        return self._get("/alerts/{}".format(alert_id)).get("data", {})

    def add_comment(self, alert_id, text):
        return self._post(
            "/alerts/{}/comments/add".format(alert_id),
            {"comment_text": text},
        )

    def append_note(self, alert_id, text, extra_payload=None):
        """Acrescenta uma entrada ao campo 'Alert note' do alerta.

        E um read-modify-write: le a nota atual, concatena e regrava. Duas
        escritas simultaneas no mesmo alerta podem perder uma entrada — o lock
        cobre este processo, o que basta para um unico bridge.
        """
        with self._note_lock:
            current = ""
            try:
                current = (self.get_alert(alert_id) or {}).get("alert_note") or ""
            except Exception as e:
                log.warning("Nao consegui ler a nota do alerta %s: %s", alert_id, e)

            new_note = (current.rstrip() + "\n\n" + text).strip() if current.strip() else text

            payload = dict(extra_payload or {})
            payload["alert_note"] = new_note
            return self.update_alert(alert_id, payload)

    def escalate_alert(self, alert_id, case_title=None, note="",
                       import_as_event=True, case_template_id=None,
                       case_tags=""):
        """Escala um alerta para um novo case no IRIS.

        Le o alerta para reaproveitar titulo, IOCs e assets, e chama o endpoint
        de escalonamento. Retorna (case_id, dados). O formato do payload segue a
        API de alertas do IRIS 2.4.x; campos ausentes sao tratados com defaults.
        """
        alert = {}
        try:
            alert = self.get_alert(alert_id) or {}
        except Exception as e:
            log.warning("Nao consegui ler o alerta %s antes de escalar: %s",
                        alert_id, e)

        title = case_title or alert.get("alert_title") or \
            "Case do alerta #{}".format(alert_id)

        # UUIDs de IOCs e assets do alerta, para importar no case quando existirem
        ioc_uuids = [
            i.get("ioc_uuid") for i in (alert.get("alert_iocs") or [])
            if i.get("ioc_uuid")
        ]
        asset_uuids = [
            a.get("asset_uuid") for a in (alert.get("alert_assets") or [])
            if a.get("asset_uuid")
        ]

        # Campos reconhecidos pela API de escalonamento do IRIS 2.4.x.
        # 'case_tags' e OBRIGATORIO: o IRIS faz case_tags.split(',') e crasha
        # com 'NoneType'...split se vier ausente. String vazia resolve.
        base = {
            "case_title": title,
            "note": note or "Escalado via Slack bridge.",
            "case_tags": case_tags or "",
        }
        # o IRIS chama len(case_template_id) — precisa ser STRING, nao int
        if case_template_id is not None:
            base["case_template_id"] = str(case_template_id)

        # Tentativa 1: importa IOCs, assets e cria evento na timeline.
        # Tentativa 2: sem imports (rede de seguranca extra).
        tentativas = [
            dict(base, import_as_event=bool(import_as_event),
                 iocs_import_list=ioc_uuids, assets_import_list=asset_uuids),
            dict(base, import_as_event=False,
                 iocs_import_list=[], assets_import_list=[]),
        ]

        ultimo_erro = None
        for payload in tentativas:
            try:
                resp = self._post("/alerts/escalate/{}".format(alert_id), payload)
                data = resp.get("data", {}) or {}
                case_id = data.get("case_id") or (data.get("case", {}) or {}).get("case_id")
                return case_id, data
            except Exception as e:
                ultimo_erro = e

        # Fallback final: o endpoint de escalonamento do IRIS crashou (bug
        # 'NoneType'...split ao processar os assets/IOCs do alerta). Cria o case
        # diretamente, referenciando o alerta na descricao. Sempre funciona.
        log.warning("Escalonamento do alerta %s falhou (%s) — criando case direto.",
                    alert_id, ultimo_erro)
        desc = "Case criado a partir do alerta #{} (Wazuh).".format(alert_id)
        if alert.get("alert_description"):
            desc += "\n\n" + str(alert["alert_description"])[:2000]
        if note:
            desc += "\n\n" + note
        return self.create_case_direct(title, desc, case_template_id=case_template_id)

    def create_case_direct(self, name, description, case_template_id=None):
        """Cria um case diretamente (/manage/cases/add), sem passar pelo alerta."""
        payload = {
            "case_name": name,
            "case_description": description or "Case criado via Slack bridge.",
            "case_customer": self.customer_id,
            "case_soc_id": "",
        }
        # o IRIS faz len(case_template_id) — precisa ser STRING
        if case_template_id is not None:
            payload["case_template_id"] = str(case_template_id)
        resp = self._post("/manage/cases/add", payload)
        data = resp.get("data", {}) or {}
        case_id = data.get("case_id") or data.get("id")
        return case_id, data

    def add_case_note(self, case_id, title, content):
        """Cria uma nota no case (usada para registrar evidencias recebidas)."""
        # IRIS agrupa notas em diretorios; cria uma nota simples no case.
        payload = {"note_title": title, "note_content": content, "cid": case_id}
        return self._post("/case/notes/add?cid={}".format(case_id), payload)

    def upload_case_evidence(self, case_id, filename, content_bytes, note=""):
        """Sobe um arquivo para o datastore do case (pasta raiz).

        O endpoint multipart varia entre versoes; tenta os formatos conhecidos
        do IRIS 2.4.x e devolve o dado da API. Levanta excecao com a mensagem do
        IRIS se todos falharem, para o chamador exibir no Slack.
        """
        import requests as _rq
        headers = {"Authorization": "Bearer {}".format(self.key)}
        last_err = None
        # parent id 1 costuma ser a pasta raiz do datastore do case
        candidatos = [
            "/case/datastore/file/add/1?cid={}".format(case_id),
            "/case/datastore/file/add?cid={}".format(case_id),
        ]
        for path in candidatos:
            try:
                files = {"file_content": (filename, content_bytes)}
                data = {"file_original_name": filename,
                        "file_description": note or "Evidencia via Slack",
                        "file_is_ioc": "false", "file_password": "",
                        "cid": str(case_id)}
                r = _rq.post(self.base + path, headers=headers, files=files,
                             data=data, verify=self.verify, timeout=60)
                if r.status_code < 300:
                    return r.json()
                last_err = "{}: {}".format(r.status_code, r.text[:300])
            except Exception as e:
                last_err = str(e)
        raise RuntimeError("upload de evidencia falhou ({})".format(last_err))

    def case_url(self, case_id):
        return "{}/case?cid={}".format(self.base_public, case_id)

    def alert_url(self, alert_id):
        return "{}/alerts?alert_id={}".format(self.base_public, alert_id)

    # base_public: URL que o analista abre no navegador (pode diferir da interna)
    base_public = None
