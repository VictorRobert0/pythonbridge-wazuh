"""Bridge Wazuh <-> Slack <-> DFIR-IRIS.

Fluxo:
  1. Wazuh POST /wazuh  -> cria alerta no IRIS -> posta no Slack (template por decoder)
  2. Botao no Slack     -> Socket Mode -> atualiza o alerta no IRIS
  3. Resposta na thread -> Socket Mode -> vira comentario no alerta do IRIS

Identidade: o bridge autentica no IRIS com uma API key administrativa, mas
atribui o alerta ao usuario IRIS correspondente ao usuario do Slack (casado
por e-mail) e registra a autoria em nota/comentario.
"""

import json
import logging
import os
import threading
import time

from flask import Flask, request, jsonify
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

import templates
from iris_client import IrisClient
from store import Store

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("bridge")

# ---------------------------------------------------------------- config

SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]
SLACK_APP_TOKEN = os.environ["SLACK_APP_TOKEN"]
SLACK_CHANNEL = os.getenv("SLACK_CHANNEL", "#soc-alerts")

IRIS_URL_INTERNAL = os.getenv("IRIS_URL_INTERNAL", "https://iris-nginx")
IRIS_URL_PUBLIC = os.getenv("IRIS_URL_PUBLIC", "https://192.168.18.10")
IRIS_API_KEY = os.environ["IRIS_API_KEY"]
IRIS_CUSTOMER_ID = int(os.getenv("IRIS_CUSTOMER_ID", "1"))

WAZUH_DASHBOARD_URL = os.getenv("WAZUH_DASHBOARD_URL", "https://192.168.18.10:4443")
DB_PATH = os.getenv("DB_PATH", "/data/bridge.db")
BRIDGE_PORT = int(os.getenv("BRIDGE_PORT", "8000"))

# Mapeamento manual opcional: {"U01ABC": "login_no_iris"}
USER_MAP = json.loads(os.getenv("SLACK_IRIS_USER_MAP", "{}"))

# Fechar abrindo modal (resolucao + nota) em vez de fechar direto.
CLOSE_WITH_MODAL = os.getenv("CLOSE_WITH_MODAL", "false").lower() in ("1", "true", "yes")

# Resolucao aplicada ao fechar sem modal. Vazio = nao definir.
IRIS_DEFAULT_RESOLUTION = os.getenv("IRIS_DEFAULT_RESOLUTION", "").strip()

iris = IrisClient(
    IRIS_URL_INTERNAL, IRIS_API_KEY, verify_ssl=False, customer_id=IRIS_CUSTOMER_ID
)
iris.base_public = IRIS_URL_PUBLIC
store = Store(DB_PATH)

bolt = App(token=SLACK_BOT_TOKEN)
flask_app = Flask(__name__)

_slack_user_cache = {}


def _stamp():
    """Carimbo de data/hora usado nas entradas da nota do alerta."""
    return time.strftime("[%d/%m/%Y %H:%M]")


# ---------------------------------------------------------------- identidade

def slack_user_info(user_id):
    if user_id in _slack_user_cache:
        return _slack_user_cache[user_id]
    try:
        r = bolt.client.users_info(user=user_id)
        u = r["user"]
        info = {
            "id": user_id,
            "name": u.get("real_name") or u.get("name") or user_id,
            "email": (u.get("profile", {}) or {}).get("email", "").strip().lower(),
        }
    except Exception as e:
        log.warning("users_info falhou para %s: %s", user_id, e)
        info = {"id": user_id, "name": user_id, "email": ""}
    _slack_user_cache[user_id] = info
    return info


def resolve_iris_user(slack_user_id):
    """Slack user -> usuario do IRIS. Retorna (iris_user|None, slack_info)."""
    info = slack_user_info(slack_user_id)

    login = USER_MAP.get(slack_user_id)
    if login:
        u = iris.user_by_login(login)
        if u:
            return u, info

    if info["email"]:
        u = iris.user_by_email(info["email"])
        if u:
            return u, info

    log.info(
        "Sem usuario IRIS para slack=%s email=%s — acao seguira sem owner",
        slack_user_id, info["email"] or "(sem email)",
    )
    return None, info


# ---------------------------------------------------------------- ingest

def build_iris_payload(alert):
    ctx = templates.Ctx(alert)
    sev = templates.severity_of(ctx.level)

    desc_lines = [
        "Regra: {} (nivel {})".format(ctx.rule_id, ctx.level),
        "Decoder: {}".format(ctx.decoder),
        "Agente: {} ({})".format(ctx.agent_name, ctx.agent_ip or "sem IP"),
        "Timestamp: {}".format(ctx.timestamp),
    ]
    if ctx.mitre:
        desc_lines.append("MITRE: {}".format(ctx.mitre))
    if ctx.event_id:
        desc_lines.append("EventID: {}".format(ctx.event_id))
    if ctx.full_log:
        desc_lines += ["", "Log:", ctx.full_log[:2000]]

    payload = {
        "alert_title": ctx.description,
        "alert_description": "\n".join(desc_lines),
        "alert_source": "Wazuh",
        "alert_source_ref": str(alert.get("id") or int(time.time())),
        "alert_source_link": WAZUH_DASHBOARD_URL,
        "alert_severity_id": sev,
        "alert_status_id": iris.status_id("new", "novo", default=2),
        "alert_customer_id": IRIS_CUSTOMER_ID,
        "alert_classification_id": 1,
        "alert_tags": "wazuh,{},rule-{},level-{}".format(
            ctx.decoder, ctx.rule_id, ctx.level
        ),
        "alert_source_content": alert,
    }

    src = ctx.d("srcip") or ctx.win("ipAddress")
    if src and src not in ("-", "::1", "127.0.0.1"):
        payload["alert_iocs"] = [
            {
                "ioc_value": src,
                "ioc_description": "IP de origem",
                "ioc_tlp_id": 2,
                "ioc_type_id": 76,
                # campos vazios (nao nulos): o escalonamento do IRIS faz .split()
                # em tags e crasha se vier None
                "ioc_tags": "",
            }
        ]

    if ctx.agent_name and ctx.agent_name != "desconhecido":
        payload["alert_assets"] = [
            {
                "asset_name": ctx.agent_name,
                "asset_description": "Agente Wazuh {}".format(ctx.agent.get("id", "")),
                "asset_type_id": 9,
                "asset_ip": ctx.agent_ip or "",
                # idem: evita o crash 'NoneType.split' no escalonamento
                "asset_tags": "",
                "asset_domain": "",
            }
        ]

    return payload, ctx


@flask_app.post("/wazuh")
def ingest():
    alert = request.get_json(force=True, silent=True)
    if not alert:
        return jsonify({"error": "json invalido"}), 400

    try:
        payload, ctx = build_iris_payload(alert)
        alert_id, _ = iris.create_alert(payload)
    except Exception as e:
        log.exception("Falha ao criar alerta no IRIS")
        return jsonify({"error": "iris: {}".format(e)}), 502

    try:
        blocks, color, fallback = templates.render(
            alert, alert_id, IRIS_URL_PUBLIC, WAZUH_DASHBOARD_URL
        )
        # Sem "text": passar text junto com attachments faz o Slack renderizar
        # uma linha extra acima do card. O fallback vai no proprio attachment,
        # que e o que aparece na notificacao e na lista de canais.
        resp = bolt.client.chat_postMessage(
            channel=SLACK_CHANNEL,
            attachments=[
                {"color": color, "fallback": fallback, "blocks": blocks}
            ],
        )
        ts = resp["ts"]
        store.link(
            ts, resp["channel"], alert_id, ctx.description,
            ctx.decoder, ctx.rule_id, ctx.level, alert,
        )
        log.info("Alerta IRIS #%s postado no Slack (ts=%s)", alert_id, ts)
    except Exception as e:
        log.exception("Falha ao postar no Slack")
        return jsonify({"alert_id": alert_id, "slack_error": str(e)}), 207

    return jsonify({"alert_id": alert_id, "slack_ts": ts}), 200


@flask_app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


# ---------------------------------------------------------------- acoes Slack

def _append_context(channel, ts, text):
    """Adiciona uma linha de contexto ao final da mensagem original."""
    try:
        hist = bolt.client.conversations_history(
            channel=channel, latest=ts, inclusive=True, limit=1
        )
        msgs = hist.get("messages", [])
        if not msgs:
            return
        msg = msgs[0]
        atts = msg.get("attachments") or []
        if atts:
            blocks = atts[0].get("blocks") or []
            blocks.append(templates.status_context_block(text))
            atts[0]["blocks"] = blocks
            # sem "text": evita reintroduzir a linha duplicada acima do card
            bolt.client.chat_update(channel=channel, ts=ts, attachments=atts)
        else:
            blocks = msg.get("blocks") or []
            blocks.append(templates.status_context_block(text))
            bolt.client.chat_update(
                channel=channel, ts=ts, text=msg.get("text", ""), blocks=blocks
            )
    except Exception:
        log.exception("Falha ao atualizar mensagem %s", ts)


def _disable_actions(channel, ts, replacement_text):
    """Remove a barra de botoes e coloca uma linha de status no lugar."""
    try:
        hist = bolt.client.conversations_history(
            channel=channel, latest=ts, inclusive=True, limit=1
        )
        msgs = hist.get("messages", [])
        if not msgs:
            return
        msg = msgs[0]
        atts = msg.get("attachments") or []
        container = atts[0] if atts else msg
        blocks = container.get("blocks") or []
        blocks = [b for b in blocks if b.get("block_id") != "alert_actions"]
        blocks.append(templates.status_context_block(replacement_text))
        if atts:
            atts[0]["blocks"] = blocks
            bolt.client.chat_update(channel=channel, ts=ts, attachments=atts)
        else:
            bolt.client.chat_update(
                channel=channel, ts=ts, text=msg.get("text", ""), blocks=blocks
            )
    except Exception:
        log.exception("Falha ao desabilitar acoes em %s", ts)


@bolt.action("open_iris")
@bolt.action("open_wazuh")
def _noop_link(ack):
    ack()  # mensagens antigas ainda podem ter esses botoes de link


@bolt.action("ack_alert")
def handle_ack(ack, body, client):
    ack()
    val = json.loads(body["actions"][0]["value"])
    alert_id = val["alert_id"]
    channel = body["channel"]["id"]
    ts = body["message"]["ts"]
    slack_uid = body["user"]["id"]

    iris_user, info = resolve_iris_user(slack_uid)

    payload = {
        "alert_status_id": iris.status_id(
            "assigned", "atribuido", "in progress", default=3
        )
    }
    if iris_user:
        payload["alert_owner_id"] = iris_user["id"]

    try:
        entry = "{} — Assumido por {} (Slack).".format(_stamp(), info["name"])
        if iris_user:
            entry += " Owner: {}.".format(iris_user["name"])
        else:
            entry += " Sem usuario IRIS correspondente — owner nao alterado."
        iris.append_note(alert_id, entry, extra_payload=payload)
    except Exception as e:
        log.exception("Falha ao assumir alerta %s", alert_id)
        client.chat_postMessage(
            channel=channel, thread_ts=ts,
            text=":x: Nao consegui assumir o alerta #{} no IRIS: `{}`".format(alert_id, e),
        )
        return

    who = iris_user["name"] if iris_user else info["name"]
    _append_context(
        channel, ts,
        ":raising_hand: Assumido por <@{}> — owner no IRIS: *{}*{}".format(
            slack_uid, who, "" if iris_user else " _(nao mapeado)_"
        ),
    )


@bolt.action("create_case")
def handle_create_case(ack, body, client):
    """Abre o modal de criacao de case, com escolha de template do IRIS."""
    ack()
    val = json.loads(body["actions"][0]["value"])
    alert_id = val["alert_id"]
    channel = body["channel"]["id"]
    ts = body["message"]["ts"]

    # titulo sugerido: o do alerta
    alerta = {}
    try:
        alerta = iris.get_alert(alert_id) or {}
    except Exception:
        pass
    titulo_sugerido = alerta.get("alert_title") or "Case do alerta #{}".format(alert_id)

    blocks = [
        {"type": "section", "text": {"type": "mrkdwn",
         "text": "Criando um case no DFIR-IRIS a partir do alerta *#{}*.".format(alert_id)}},
        {
            "type": "input",
            "block_id": "titulo",
            "label": {"type": "plain_text", "text": "Titulo do case"},
            "element": {
                "type": "plain_text_input",
                "action_id": "value",
                "initial_value": titulo_sugerido[:250],
            },
        },
    ]

    # dropdown de templates apenas se o IRIS tiver algum
    try:
        templates_iris = iris.list_case_templates()
    except Exception:
        templates_iris = []
    if templates_iris:
        opcoes = [
            {"text": {"type": "plain_text", "text": nome[:70]}, "value": str(tid)}
            for tid, nome in templates_iris[:100]
        ]
        blocks.append({
            "type": "input",
            "block_id": "template",
            "optional": True,
            "label": {"type": "plain_text", "text": "Template (opcional)"},
            "element": {
                "type": "static_select",
                "action_id": "value",
                "placeholder": {"type": "plain_text", "text": "Sem template"},
                "options": opcoes,
            },
        })

    blocks.append({
        "type": "input",
        "block_id": "note",
        "optional": True,
        "label": {"type": "plain_text", "text": "Nota de escalonamento"},
        "element": {
            "type": "plain_text_input", "action_id": "value", "multiline": True,
            "placeholder": {"type": "plain_text", "text": "Por que virou case?"},
        },
    })

    client.views_open(
        trigger_id=body["trigger_id"],
        view={
            "type": "modal",
            "callback_id": "create_case_modal",
            "private_metadata": json.dumps(
                {"alert_id": alert_id, "channel": channel, "ts": ts}),
            "title": {"type": "plain_text", "text": "Criar case"},
            "submit": {"type": "plain_text", "text": "Criar"},
            "close": {"type": "plain_text", "text": "Cancelar"},
            "blocks": blocks,
        },
    )


@bolt.view("create_case_modal")
def handle_create_case_submit(ack, body, view, client):
    ack()
    meta = json.loads(view["private_metadata"])
    alert_id, channel, ts = meta["alert_id"], meta["channel"], meta["ts"]
    slack_uid = body["user"]["id"]
    values = view["state"]["values"]

    titulo = (values["titulo"]["value"].get("value") or "").strip() or None
    nota = (values.get("note", {}).get("value", {}) or {}).get("value") or ""
    template_id = None
    if "template" in values:
        sel = values["template"]["value"].get("selected_option")
        if sel:
            template_id = int(sel["value"])

    iris_user, info = resolve_iris_user(slack_uid)
    note_iris = "Case criado por {} (Slack).".format(info["name"])
    if iris_user:
        note_iris += " Usuario IRIS: {}.".format(iris_user["name"])
    if nota:
        note_iris += " " + nota

    try:
        case_id, _ = iris.escalate_alert(
            alert_id, case_title=titulo, note=note_iris,
            case_template_id=template_id)
        iris.append_note(alert_id, "{} {}".format(_stamp(), note_iris))
        if case_id:
            store.set_case(alert_id, case_id)
    except Exception as e:
        log.exception("Falha ao criar case do alerta %s", alert_id)
        client.chat_postMessage(
            channel=channel, thread_ts=ts,
            text=":x: Nao consegui criar o case do alerta #{} no IRIS: `{}`".format(
                alert_id, e))
        return

    link = ("<{}/case?cid={}|case #{}>".format(IRIS_URL_PUBLIC.rstrip("/"), case_id, case_id)
            if case_id else "o case")
    _append_context(
        channel, ts,
        ":file_folder: <@{}> criou {} no IRIS a partir deste alerta.".format(slack_uid, link))


@bolt.action("close_alert")
def handle_close(ack, body, client):
    """Fecha o alerta direto. O contexto vem das respostas na thread."""
    ack()
    if CLOSE_WITH_MODAL:
        return _open_close_modal(body, client)

    val = json.loads(body["actions"][0]["value"])
    alert_id = val["alert_id"]
    channel = body["channel"]["id"]
    ts = body["message"]["ts"]
    slack_uid = body["user"]["id"]

    iris_user, info = resolve_iris_user(slack_uid)

    payload = {"alert_status_id": iris.status_id("closed", "fechado", default=6)}
    if iris_user:
        payload["alert_owner_id"] = iris_user["id"]
    if IRIS_DEFAULT_RESOLUTION:
        rid = iris.resolution_id(IRIS_DEFAULT_RESOLUTION)
        if rid is not None:
            payload["alert_resolution_status_id"] = rid

    try:
        entry = "{} — Fechado por {} (Slack).".format(_stamp(), info["name"])
        if iris_user:
            entry += " Usuario IRIS: {}.".format(iris_user["name"])
        iris.append_note(alert_id, entry, extra_payload=payload)
    except Exception as e:
        log.exception("Falha ao fechar alerta %s", alert_id)
        client.chat_postMessage(
            channel=channel, thread_ts=ts,
            text=":x: Nao consegui fechar o alerta #{} no IRIS: `{}`".format(alert_id, e),
        )
        return

    who = iris_user["name"] if iris_user else info["name"]
    _disable_actions(
        channel, ts,
        ":white_check_mark: Fechado por <@{}> — no IRIS: *{}*{}".format(
            slack_uid, who, "" if iris_user else " _(nao mapeado)_"
        ),
    )


def _open_close_modal(body, client):
    """Modal de fechamento com resolucao e nota. Em standby: ativar com
    CLOSE_WITH_MODAL=true no .env."""
    val = json.loads(body["actions"][0]["value"])
    alert_id = val["alert_id"]
    channel = body["channel"]["id"]
    ts = body["message"]["ts"]

    iris.load_lookups()
    # Rotulos amigaveis para as resolucoes padrao do IRIS
    catalogo = [
        ("False Positive", "Falso positivo"),
        ("True Positive With Impact", "Verdadeiro positivo (com impacto)"),
        ("True Positive Without Impact", "Verdadeiro positivo (sem impacto)"),
        ("Legitimate", "Atividade legitima"),
        ("Not Applicable", "Nao aplicavel"),
        ("Unknown", "Indeterminado"),
    ]

    def montar_opcoes():
        out = []
        for nome_iris, rotulo in catalogo:
            rid = iris.resolution_id(nome_iris)
            if rid is not None:
                out.append(
                    {"text": {"type": "plain_text", "text": rotulo}, "value": str(rid)}
                )
        return out

    opts = montar_opcoes()
    if not opts:
        # mapa vazio (IRIS indisponivel no boot) — forca recarregar e tenta de novo
        log.warning("Resolucoes vazias ao abrir o modal — recarregando lookups.")
        iris.load_lookups(force=True)
        opts = montar_opcoes()
    if not opts:
        opts = [{"text": {"type": "plain_text", "text": "Nao especificado"}, "value": "1"}]

    client.views_open(
        trigger_id=body["trigger_id"],
        view={
            "type": "modal",
            "callback_id": "close_alert_modal",
            "private_metadata": json.dumps(
                {"alert_id": alert_id, "channel": channel, "ts": ts}
            ),
            "title": {"type": "plain_text", "text": "Fechar alerta"},
            "submit": {"type": "plain_text", "text": "Fechar"},
            "close": {"type": "plain_text", "text": "Cancelar"},
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "Fechando o alerta *#{}* no DFIR-IRIS.".format(alert_id),
                    },
                },
                {
                    "type": "input",
                    "block_id": "resolution",
                    "label": {"type": "plain_text", "text": "Resolucao"},
                    "element": {
                        "type": "static_select",
                        "action_id": "value",
                        "options": opts,
                        "initial_option": opts[0],
                    },
                },
                {
                    "type": "input",
                    "block_id": "note",
                    "optional": True,
                    "label": {"type": "plain_text", "text": "Nota de fechamento"},
                    "element": {
                        "type": "plain_text_input",
                        "action_id": "value",
                        "multiline": True,
                        "placeholder": {
                            "type": "plain_text",
                            "text": "O que foi apurado? Qual a conclusao?",
                        },
                    },
                },
            ],
        },
    )


@bolt.view("close_alert_modal")
def handle_close_submit(ack, body, view, client):
    ack()
    meta = json.loads(view["private_metadata"])
    alert_id, channel, ts = meta["alert_id"], meta["channel"], meta["ts"]
    slack_uid = body["user"]["id"]

    values = view["state"]["values"]
    escolha = values["resolution"]["value"]["selected_option"]
    resolution_id = int(escolha["value"])
    resolution_label = escolha["text"]["text"]
    note = (values["note"]["value"].get("value") or "").strip()

    iris_user, info = resolve_iris_user(slack_uid)

    payload = {
        "alert_status_id": iris.status_id("closed", "fechado", default=6),
        "alert_resolution_status_id": resolution_id,
    }
    if iris_user:
        payload["alert_owner_id"] = iris_user["id"]

    try:
        entry = "{} Fechado por {} (Slack). Resolucao: {}.".format(
            _stamp(), info["name"], resolution_label
        )
        if iris_user:
            entry += " Usuario IRIS: {}.".format(iris_user["name"])
        if note:
            entry += "\n{}".format(note)
        iris.append_note(alert_id, entry, extra_payload=payload)
    except Exception as e:
        log.exception("Falha ao fechar alerta %s", alert_id)
        client.chat_postMessage(
            channel=channel, thread_ts=ts,
            text=":x: Nao consegui fechar o alerta #{} no IRIS: `{}`".format(alert_id, e),
        )
        return

    who = iris_user["name"] if iris_user else info["name"]
    txt = ":white_check_mark: Fechado por <@{}> como *{}* · IRIS: *{}*{}".format(
        slack_uid, resolution_label, who,
        "" if iris_user else " _(nao mapeado)_"
    )
    if note:
        txt += "\n> {}".format(note.replace("\n", "\n> ")[:600])
    _disable_actions(channel, ts, txt)


# ---------------------------------------------------------------- thread -> IRIS

def _download_slack_file(url):
    """Baixa um arquivo privado do Slack usando o token do bot."""
    import requests as _rq
    r = _rq.get(url, headers={"Authorization": "Bearer {}".format(SLACK_BOT_TOKEN)},
                timeout=60)
    r.raise_for_status()
    return r.content


def _ensure_case(alert_id, autor):
    """Garante que existe um case para o alerta (cria se preciso). Retorna case_id."""
    case_id = store.get_case(alert_id)
    if case_id:
        return case_id
    nota = "Case criado automaticamente para anexar evidencia enviada por {} (Slack).".format(autor)
    case_id, _ = iris.escalate_alert(alert_id, note=nota)
    if case_id:
        store.set_case(alert_id, case_id)
        iris.append_note(alert_id, "{} {}".format(_stamp(), nota))
    return case_id


def _handle_thread_files(event, link, client, autor):
    """Encaminha imagens/anexos da thread para o case do alerta no IRIS."""
    files = event.get("files") or []
    imagens = [f for f in files if (f.get("mimetype") or "").startswith("image/")
               or (f.get("filetype") or "") in ("png", "jpg", "jpeg", "gif", "webp", "bmp")]
    # tambem aceita outros anexos como evidencia
    outros = [f for f in files if f not in imagens]
    todos = imagens + outros
    if not todos:
        return

    channel, ts = event["channel"], event["ts"]
    try:
        case_id = _ensure_case(link["alert_id"], autor)
    except Exception as e:
        log.exception("Falha ao garantir case para evidencia (alerta %s)", link["alert_id"])
        client.chat_postMessage(
            channel=channel, thread_ts=event.get("thread_ts"),
            text=":x: Nao consegui preparar o case para anexar a evidencia: `{}`".format(e))
        return

    ok = 0
    for f in todos:
        nome = f.get("name") or "evidencia"
        url = f.get("url_private_download") or f.get("url_private")
        if not url:
            continue
        try:
            conteudo = _download_slack_file(url)
            iris.upload_case_evidence(
                case_id, nome, conteudo,
                note="Evidencia enviada por {} (Slack) no alerta #{}".format(
                    autor, link["alert_id"]))
            ok += 1
        except Exception as e:
            log.exception("Falha ao enviar evidencia %s ao IRIS", nome)
            client.chat_postMessage(
                channel=channel, thread_ts=event.get("thread_ts"),
                text=":x: Nao consegui anexar `{}` ao IRIS: `{}`".format(nome, e))

    if ok:
        iris.append_note(
            link["alert_id"],
            "{} — {} anexou {} evidencia(s) ao case #{} (Slack).".format(
                _stamp(), autor, ok, case_id))
        try:
            client.reactions_add(channel=channel, timestamp=ts, name="paperclip")
        except Exception:
            pass


@bolt.event("message")
def handle_thread_reply(event, client):
    # so respostas em thread, de humanos (aceita upload de arquivo = subtype file_share)
    thread_ts = event.get("thread_ts")
    subtype = event.get("subtype")
    if not thread_ts or event.get("bot_id"):
        return
    if subtype and subtype != "file_share":
        return

    link = store.by_thread(thread_ts)
    if not link:
        return

    key = "{}:{}".format(event.get("channel"), event.get("ts"))
    if store.seen(key):
        return

    slack_uid = event.get("user")
    iris_user, info = resolve_iris_user(slack_uid)
    author = iris_user["name"] if iris_user else info["name"]

    # 1. anexos (imagens/evidencias) -> case no IRIS
    if event.get("files"):
        _handle_thread_files(event, link, client, author)

    # 2. texto -> nota do alerta
    text = (event.get("text") or "").strip()
    if not text:
        return
    entry = "{} — {} (Slack):\n{}".format(_stamp(), author, text)
    try:
        iris.append_note(link["alert_id"], entry)
        client.reactions_add(
            channel=event["channel"], timestamp=event["ts"], name="inbox_tray"
        )
    except Exception as e:
        log.exception("Falha ao comentar no alerta %s", link["alert_id"])
        try:
            client.reactions_add(
                channel=event["channel"], timestamp=event["ts"], name="warning"
            )
        except Exception:
            pass


# ---------------------------------------------------------------- boot

def run_flask():
    from waitress import serve
    log.info("Ingest HTTP escutando em 0.0.0.0:%s", BRIDGE_PORT)
    serve(flask_app, host="0.0.0.0", port=BRIDGE_PORT, threads=8)


if __name__ == "__main__":
    try:
        iris.load_lookups()
    except Exception:
        log.warning("Lookups do IRIS falharam no boot — tentara sob demanda")

    threading.Thread(target=run_flask, daemon=True).start()
    log.info("Conectando ao Slack via Socket Mode...")
    SocketModeHandler(bolt, SLACK_APP_TOKEN).start()
