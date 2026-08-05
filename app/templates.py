"""Templates de Block Kit por decoder.name.

Registro: DECODER -> funcao(ctx) -> lista de blocks do corpo.
O cabecalho, o rodape e a barra de acoes sao comuns e montados em render().

Para adicionar um decoder novo:

    @template("nome_do_decoder")
    def _meu_decoder(ctx):
        return [ ...blocks... ]
"""

import json
import os
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

# ---------------------------------------------------------------- helpers

SEVERITY = {
    5: ("CRITICAL", "#B31C1C", ":rotating_light:"),
    4: ("HIGH", "#E8590C", ":red_circle:"),
    3: ("MEDIUM", "#F59F00", ":large_orange_circle:"),
    2: ("LOW", "#2F9E44", ":large_green_circle:"),
    1: ("INFO", "#868E96", ":white_circle:"),
}

# decoder.name -> rotulo exibido no titulo
SOURCE_LABELS = {
    "windows_eventchannel": "WINDOWS",
    "docker-listener": "DOCKER",
    "docker": "DOCKER",
    "sshd": "SSH",
    "web-accesslog": "WEB",
    "apache-accesslog": "WEB",
    "nginx-accesslog": "WEB",
    "syscheck_integrity_changed": "FIM",
    "syscheck_new_entry": "FIM",
    "syscheck_deleted": "FIM",
    "ossec": "OSSEC",
    "json": "JSON",
}

# Canais do Event Log que merecem rotulo proprio
WIN_CHANNEL_LABELS = {
    "security": "WINDOWS SECURITY",
    "microsoft-windows-sysmon/operational": "SYSMON",
    "microsoft-windows-powershell/operational": "POWERSHELL",
    "windows powershell": "POWERSHELL",
    "system": "WINDOWS SYSTEM",
    "application": "WINDOWS APP",
}

# Agentes que sao Domain Controller. Eventos do canal Security vindos deles
# sao rotulados como ACTIVE DIRECTORY. Lista separada por virgula no .env.
DC_AGENTS = {
    a.strip().lower()
    for a in os.getenv("DC_AGENTS", "dc01-ad").split(",")
    if a.strip()
}

# EventIDs que so existem em Domain Controller (Kerberos e Directory Service).
# Servem de sinal quando o agente nao esta na lista acima.
AD_ONLY_EVENT_IDS = {
    "4662",   # operacao em objeto do AD
    "4768", "4769", "4770", "4771", "4772", "4773",  # Kerberos
    "4776", "4777",                                   # validacao de credencial
    "4781",                                           # nome de conta alterado
    "5136", "5137", "5138", "5139", "5141",           # mudancas no Directory Service
}


def source_label(ctx):
    """Rotulo curto da origem do alerta, usado entre colchetes no titulo."""
    if ctx.decoder == "windows_eventchannel":
        channel = str(ctx.win_system.get("channel", "") or "").strip().lower()
        if channel == "security":
            is_dc = (
                str(ctx.agent_name or "").strip().lower() in DC_AGENTS
                or ctx.event_id in AD_ONLY_EVENT_IDS
            )
            return "ACTIVE DIRECTORY" if is_dc else "WINDOWS SECURITY"
        label = WIN_CHANNEL_LABELS.get(channel)
        if label:
            return label
        return "WINDOWS"
    label = SOURCE_LABELS.get(ctx.decoder)
    if label:
        return label
    # fallback: o proprio decoder, normalizado
    return re.sub(r"[_\-]+", " ", str(ctx.decoder or "DESCONHECIDO")).upper()[:28]


def severity_of(level):
    level = int(level or 0)
    if level >= 15:
        return 5
    if level >= 12:
        return 4
    if level >= 8:
        return 3
    if level >= 5:
        return 2
    return 1


def _t(s, limit=2900):
    """Trunca texto para caber nos limites do Slack."""
    if s is None:
        return "-"
    s = str(s)
    return s if len(s) <= limit else s[: limit - 3] + "..."


def _code(s, limit=2800):
    s = _t(s, limit)
    return "```{}```".format(s.replace("```", "'''"))


def section(text):
    return {"type": "section", "text": {"type": "mrkdwn", "text": _t(text)}}


def fields(pairs):
    """pairs: [(label, value), ...] -> blocos de section com fields (max 10 por bloco)."""
    out = []
    clean = [(k, v) for k, v in pairs if v not in (None, "", "-")]
    for i in range(0, len(clean), 10):
        chunk = clean[i : i + 10]
        out.append(
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": "*{}*\n{}".format(k, _t(v, 1900))}
                    for k, v in chunk
                ],
            }
        )
    return out


def context(elements):
    return {
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": _t(e, 900)} for e in elements if e],
    }


# ------------------------------------------------- link para o Wazuh

# Janela de tempo (minutos) aplicada antes e depois do alerta.
WAZUH_WINDOW_MIN = int(os.getenv("WAZUH_WINDOW_MIN", "30"))

# Rota do Discover. Varia entre versoes do OpenSearch Dashboards:
#   data-explorer  -> Wazuh 4.8+ (padrao)
#   classic        -> instalacoes mais antigas (/app/discover)
WAZUH_DISCOVER_ROUTE = os.getenv("WAZUH_DISCOVER_ROUTE", "data-explorer")

WAZUH_INDEX = os.getenv("WAZUH_INDEX_PATTERN", "wazuh-alerts-*")

_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*"
    r"([+-]\d{2}:?\d{2}|Z)?$"
)


def _parse_ts(ts):
    """Converte o timestamp do Wazuh para datetime UTC. None se nao der."""
    if not ts:
        return None
    m = _TS_RE.match(str(ts).strip())
    if not m:
        return None
    date_part, time_part, frac, off = m.groups()
    try:
        dt = datetime.strptime(date_part + " " + time_part, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    if frac:
        dt = dt.replace(microsecond=int((frac + "000000")[:6]))
    if off and off != "Z":
        off = off.replace(":", "")
        sign = 1 if off[0] == "+" else -1
        delta = timedelta(hours=int(off[1:3]), minutes=int(off[3:5]))
        dt = dt.replace(tzinfo=timezone(sign * delta))
    else:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _rison_str(s):
    """Escapa uma string para RISON (aspas simples)."""
    return "'" + str(s).replace("\\", "\\\\").replace("'", "\\'") + "'"


def build_query(ctx):
    """Monta a query KQL que isola os eventos relacionados ao alerta."""
    parts = []
    agent_id = (ctx.agent or {}).get("id")
    if agent_id:
        parts.append("agent.id:{}".format(agent_id))
    elif ctx.agent_name and ctx.agent_name != "desconhecido":
        parts.append('agent.name:"{}"'.format(ctx.agent_name))
    if ctx.rule_id and ctx.rule_id != "N/A":
        parts.append("rule.id:{}".format(ctx.rule_id))
    if ctx.event_id:
        parts.append("data.win.system.eventID:{}".format(ctx.event_id))
    return " and ".join(parts) or "*"


def wazuh_discover_url(base_url, ctx):
    """URL do Discover do Wazuh ja filtrada no agente, regra e janela do alerta."""
    base = (base_url or "").rstrip("/")
    query = build_query(ctx)

    dt = _parse_ts(ctx.timestamp)
    if dt:
        frm = (dt - timedelta(minutes=WAZUH_WINDOW_MIN)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        )
        to = (dt + timedelta(minutes=WAZUH_WINDOW_MIN)).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z"
        )
        time_rison = "(from:{},to:{})".format(_rison_str(frm), _rison_str(to))
    else:
        time_rison = "(from:now-24h,to:now)"

    g = "(filters:!(),refreshInterval:(pause:!t,value:0),time:{})".format(time_rison)
    q = "(filters:!(),query:(language:kuery,query:{}))".format(_rison_str(query))

    if WAZUH_DISCOVER_ROUTE == "classic":
        a = (
            "(columns:!(agent.name,rule.level,rule.description),"
            "index:{},interval:auto,sort:!(!('@timestamp',desc)))"
        ).format(_rison_str(WAZUH_INDEX))
        frag = "/app/discover#/?_g={}&_a={}&_q={}".format(
            quote(g, safe="(),:!*'-_.~"),
            quote(a, safe="(),:!*'-_.~"),
            quote(q, safe="(),:!*'-_.~"),
        )
    else:
        a = (
            "(discover:(columns:!(agent.name,rule.level,rule.description),"
            "isDirty:!f,sort:!()),metadata:(indexPattern:{},view:discover))"
        ).format(_rison_str(WAZUH_INDEX))
        frag = "/app/data-explorer/discover#?_g={}&_q={}&_a={}".format(
            quote(g, safe="(),:!*'-_.~"),
            quote(q, safe="(),:!*'-_.~"),
            quote(a, safe="(),:!*'-_.~"),
        )

    return base + frag


# ---------------------------------------------------------------- registro

_REGISTRY = {}


def template(*decoder_names):
    def deco(fn):
        for n in decoder_names:
            _REGISTRY[n] = fn
        return fn

    return deco


# ---------------------------------------------------------------- contexto

class Ctx:
    """Visao normalizada do alerta do Wazuh."""

    def __init__(self, alert):
        self.alert = alert or {}
        self.rule = self.alert.get("rule", {}) or {}
        self.agent = self.alert.get("agent", {}) or {}
        self.data = self.alert.get("data", {}) or {}
        self.decoder = (self.alert.get("decoder", {}) or {}).get("name") or "unknown"
        self.level = int(self.rule.get("level", 0) or 0)
        self.rule_id = self.rule.get("id", "N/A")
        self.description = self.rule.get("description", "Alerta Wazuh")
        self.agent_name = self.agent.get("name", "desconhecido")
        self.agent_ip = self.agent.get("ip", "")
        self.timestamp = self.alert.get("timestamp", "")
        self.full_log = self.alert.get("full_log", "")
        self.location = self.alert.get("location", "")

        win = self.data.get("win", {}) or {}
        self.win_system = win.get("system", {}) or {}
        self.win_event = win.get("eventdata", {}) or {}
        self.event_id = str(self.win_system.get("eventID", "") or "")

    @property
    def mitre(self):
        m = self.rule.get("mitre", {}) or {}
        tech = m.get("technique") or []
        ids = m.get("id") or []
        if not tech and not ids:
            return None
        pairs = []
        for i, t in enumerate(tech):
            tid = ids[i] if i < len(ids) else ""
            pairs.append("{} ({})".format(t, tid) if tid else t)
        return ", ".join(pairs)

    def win(self, *keys, default=None):
        for k in keys:
            v = self.win_event.get(k)
            if v not in (None, "", "-"):
                return v
        return default

    def d(self, *keys, default=None):
        for k in keys:
            v = self.data.get(k)
            if v not in (None, "", "-"):
                return v
        return default


# ---------------------------------------------------------------- templates

WIN_EVENT_LABELS = {
    "4624": ("Logon bem-sucedido", ":unlock:"),
    "4625": ("Falha de logon", ":no_entry:"),
    "4634": ("Logoff", ":wave:"),
    "4648": ("Logon com credencial explicita", ":key:"),
    "4672": ("Privilegios especiais atribuidos", ":crown:"),
    "4720": ("Conta de usuario criada", ":bust_in_silhouette:"),
    "4722": ("Conta habilitada", ":white_check_mark:"),
    "4723": ("Tentativa de troca de senha", ":closed_lock_with_key:"),
    "4724": ("Reset de senha por administrador", ":closed_lock_with_key:"),
    "4725": ("Conta desabilitada", ":no_pedestrians:"),
    "4726": ("Conta de usuario excluida", ":wastebasket:"),
    "4728": ("Membro adicionado a grupo global", ":busts_in_silhouette:"),
    "4732": ("Membro adicionado a grupo local", ":busts_in_silhouette:"),
    "4756": ("Membro adicionado a grupo universal", ":busts_in_silhouette:"),
    "4740": ("Conta bloqueada", ":lock:"),
    "4767": ("Conta desbloqueada", ":unlock:"),
    "4768": ("Ticket Kerberos TGT solicitado", ":ticket:"),
    "4769": ("Ticket Kerberos de servico solicitado", ":ticket:"),
    "4771": ("Falha de pre-autenticacao Kerberos", ":no_entry_sign:"),
    "4776": ("Validacao de credencial NTLM", ":shield:"),
    "1102": ("Log de auditoria limpo", ":fire:"),
    "4104": ("PowerShell ScriptBlock", ":scroll:"),
    "4688": ("Novo processo criado", ":gear:"),
}

LOGON_TYPES = {
    "2": "Interativo (console)",
    "3": "Rede",
    "4": "Batch",
    "5": "Servico",
    "7": "Desbloqueio",
    "8": "Rede em texto claro",
    "9": "NewCredentials",
    "10": "Remoto interativo (RDP)",
    "11": "Interativo em cache",
}

PRIVILEGED_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "administradores", "account operators",
    "backup operators", "print operators", "server operators",
    "group policy creator owners", "dnsadmins",
}


@template("windows_eventchannel")
def _windows_eventchannel(ctx):
    label, emoji = WIN_EVENT_LABELS.get(
        ctx.event_id, ("Evento do Windows", ":window:")
    )

    target = ctx.win("targetUserName", "targetUser")
    subject = ctx.win("subjectUserName")
    src_ip = ctx.win("ipAddress", "workstationName")
    logon_type = str(ctx.win("logonType", default="") or "")
    group = ctx.win("targetGroupName", "groupName")
    process = ctx.win("processName", "newProcessName")
    status = ctx.win("status", "subStatus")

    blocks = [
        section(
            "{} *{}*  ·  EventID `{}`  ·  canal `{}`".format(
                emoji, label, ctx.event_id or "?",
                ctx.win_system.get("channel", "-"),
            )
        )
    ]

    pairs = [
        ("Usuario alvo", target),
        ("Executado por", subject),
        ("IP / Origem", src_ip),
        (
            "Tipo de logon",
            "{} - {}".format(logon_type, LOGON_TYPES[logon_type])
            if logon_type in LOGON_TYPES
            else logon_type,
        ),
        ("Grupo", group),
        ("Processo", process),
        ("Status", status),
        ("Dominio alvo", ctx.win("targetDomainName")),
    ]
    blocks += fields(pairs)

    # Destaque para adicao em grupo privilegiado
    if group and str(group).strip().lower() in PRIVILEGED_GROUPS:
        blocks.append(
            section(
                ":warning: *Escalacao de privilegio* — `{}` foi adicionado ao grupo "
                "privilegiado *{}*. Validar se a mudanca foi autorizada.".format(
                    target or "?", group
                )
            )
        )

    if ctx.event_id == "1102":
        blocks.append(
            section(
                ":fire: *Log de auditoria foi limpo.* Tecnica classica de "
                "anti-forense — tratar como incidente ate prova em contrario."
            )
        )

    if ctx.event_id == "4104":
        script = ctx.win("scriptBlockText")
        if script:
            blocks.append(section("*ScriptBlock*\n" + _code(script, 2000)))

    return blocks


@template("docker-listener", "docker")
def _docker(ctx):
    dk = ctx.data.get("docker", {}) or ctx.alert.get("docker", {}) or {}
    actor = (dk.get("Actor", {}) or {}).get("Attributes", {}) or {}
    return [
        section(
            ":whale: *{} / {}*".format(
                dk.get("Type", "-"), dk.get("Action", "-")
            )
        )
    ] + fields(
        [
            ("Container", actor.get("name")),
            ("Imagem", actor.get("image")),
            ("Tipo", dk.get("Type")),
            ("Acao", dk.get("Action")),
            ("Escopo", dk.get("scope")),
            ("Exit code", actor.get("exitCode")),
        ]
    )


@template("sshd")
def _sshd(ctx):
    return [section(":closed_lock_with_key: *Atividade SSH*")] + fields(
        [
            ("Usuario", ctx.d("dstuser", "srcuser")),
            ("IP origem", ctx.d("srcip")),
            ("Porta", ctx.d("srcport")),
            ("Protocolo", ctx.d("protocol")),
        ]
    )


@template("web-accesslog", "apache-accesslog", "nginx-accesslog")
def _web(ctx):
    return [section(":globe_with_meridians: *Requisicao web suspeita*")] + fields(
        [
            ("IP origem", ctx.d("srcip")),
            ("URL", ctx.d("url")),
            ("Metodo", ctx.d("protocol")),
            ("Status HTTP", ctx.d("id")),
            ("User-Agent", ctx.d("user_agent")),
        ]
    )


@template("syscheck_integrity_changed", "syscheck_new_entry", "syscheck_deleted")
def _syscheck(ctx):
    sc = ctx.data.get("syscheck", {}) or ctx.alert.get("syscheck", {}) or {}
    return [section(":mag: *Integridade de arquivo (FIM)*")] + fields(
        [
            ("Arquivo", sc.get("path")),
            ("Evento", sc.get("event")),
            ("MD5 antes", sc.get("md5_before")),
            ("MD5 depois", sc.get("md5_after")),
            ("Dono", sc.get("uname_after") or sc.get("uname_before")),
            ("Tamanho", sc.get("size_after")),
        ]
    )


def _generic(ctx):
    """Fallback para qualquer decoder sem template proprio."""
    blocks = [section(":page_facing_up: *{}*".format(ctx.description))]
    pairs = [
        ("Decoder", ctx.decoder),
        ("Localizacao", ctx.location),
        ("IP origem", ctx.d("srcip")),
        ("Usuario", ctx.d("dstuser", "srcuser")),
    ]
    blocks += fields(pairs)
    return blocks


# ---------------------------------------------------------------- render

def render(alert, iris_alert_id, iris_url, wazuh_url, extra_context=None):
    """Monta a mensagem completa do Slack.

    Retorna (blocks, attachment_color, fallback_text).
    """
    ctx = Ctx(alert)
    sev = severity_of(ctx.level)
    sev_name, color, sev_emoji = SEVERITY[sev]

    # Titulo em linha unica: #ID [ORIGEM] [SEVERIDADE] - Descricao
    # Todo ele e um hyperlink para o Discover do Wazuh ja filtrado.
    title = "#{} [{}] [{}] - {}".format(
        iris_alert_id, source_label(ctx), sev_name, _t(ctx.description, 200)
    )
    # '|' e '>' quebram o link mrkdwn do Slack
    safe_title = title.replace("|", "/").replace(">", "")
    hunt_url = wazuh_discover_url(wazuh_url, ctx)

    # Header block nao aceita link — section com mrkdwn resolve.
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "*<{}|{}>*".format(hunt_url, safe_title),
            },
        },
        context(
            [
                "regra `{}`".format(ctx.rule_id),
                "nivel {}".format(ctx.level),
                "decoder `{}`".format(ctx.decoder),
                "agente *{}*{}".format(
                    ctx.agent_name, " (`{}`)".format(ctx.agent_ip) if ctx.agent_ip else ""
                ),
                ctx.timestamp[:19].replace("T", " ") if ctx.timestamp else None,
            ]
        ),
        {"type": "divider"},
    ]

    builder = _REGISTRY.get(ctx.decoder, _generic)
    try:
        blocks += builder(ctx)
    except Exception as e:  # template quebrado nunca deve impedir o alerta
        blocks += _generic(ctx)
        blocks.append(context([":warning: template `{}` falhou: {}".format(ctx.decoder, e)]))

    if ctx.mitre:
        blocks.append(context([":dart: MITRE ATT&CK: {}".format(ctx.mitre)]))

    if ctx.full_log:
        blocks.append(section("*Log bruto*\n" + _code(ctx.full_log, 1500)))

    if extra_context:
        blocks.append(context([extra_context]))

    # Barra de acoes — apenas Assumir e Fechar. Os links (IRIS e Wazuh) ficam
    # no titulo e na linha de contexto para nao poluir a mensagem.
    val = json.dumps({"alert_id": iris_alert_id})
    blocks.append(
        {
            "type": "actions",
            "block_id": "alert_actions",
            "elements": [
                {
                    "type": "button",
                    "action_id": "ack_alert",
                    "text": {"type": "plain_text", "text": "Assumir", "emoji": True},
                    "style": "primary",
                    "value": val,
                },
                {
                    "type": "button",
                    "action_id": "create_case",
                    "text": {"type": "plain_text", "text": "Criar case", "emoji": True},
                    "value": val,
                },
                {
                    "type": "button",
                    "action_id": "close_alert",
                    "text": {"type": "plain_text", "text": "Fechar", "emoji": True},
                    "value": val,
                },
            ],
        }
    )
    blocks.append(
        context(
            [
                "<{}/alerts?alert_id={}|Abrir no IRIS>".format(
                    iris_url.rstrip("/"), iris_alert_id
                ),
                "·  responda nesta thread para registrar na nota do alerta",
            ]
        )
    )

    # Texto usado so na notificacao do Slack (push / lista de canais).
    # Nao vira uma linha extra na mensagem porque nao passamos "text".
    fallback = "{} — agente {}".format(title, ctx.agent_name)
    return blocks, color, fallback


def status_context_block(text):
    """Bloco de contexto usado para registrar acoes na mensagem."""
    return context([text])
