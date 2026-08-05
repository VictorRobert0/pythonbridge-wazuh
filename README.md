# SOC Bridge — Wazuh → DFIR-IRIS → Slack

Alertas do Wazuh viram alertas no IRIS e mensagens no Slack com template por
`decoder.name`. Os botões atualizam o alerta no IRIS em nome de quem clicou,
respostas na thread entram na nota do alerta, e imagens viram evidência no case.

> Para montar o ambiente do zero (AD, agente Wazuh, IRIS, bridge), veja
> [RUNBOOK-REPLICACAO.md](RUNBOOK-REPLICACAO.md).

## Quickstart

Pré-requisitos: Docker, um stack de SOC com **Wazuh** e **DFIR-IRIS** rodando, e
permissão para criar um app no seu workspace do **Slack**.

```bash
# 1. Crie o app do Slack a partir de slack-app-manifest.yml
#    (api.slack.com/apps -> From an app manifest), gere os tokens xoxb- e xapp-,
#    e convide o bot no canal de alertas.

# 2. Configure e suba (Windows PowerShell)
./setup.ps1                          # cria o .env, valida, faz build e sobe
./setup.ps1 -InstallWazuh            # + instala a integração no Wazuh Manager

# 2. (Linux/Mac)
./setup.sh
./setup.sh --install-wazuh
```

O `setup` cria o `.env` a partir do `.env.example` na primeira execução e abre
para você preencher `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN` e `IRIS_API_KEY`. Rode
de novo e ele valida, builda e sobe. Detalhes de cada variável na seção
[Configuração](#configuração-env).

---

## Arquitetura

```
                        ┌──────────────────────────────┐
 Wazuh Manager          │      slack-iris-bridge       │
 (regra nível ≥ 7)      │                              │
        │               │  Flask :8000  ──► /wazuh     │
        │  custom-bridge│         │                    │
        └──── HTTP ────►│         ├──► IRIS /alerts/add│──► DFIR-IRIS
                        │         │     (devolve o ID) │
                        │         └──► Slack chat.post │──► #soc-alerts
                        │                              │
                        │  Socket Mode (WebSocket)     │
   Slack ◄──────────────┤    ◄── botão Assumir/Fechar  │
   (clique / thread)    │    ◄── resposta em thread    │
                        │         │                    │
                        │         └──► IRIS alert_note │──► DFIR-IRIS
                        └──────────────────────────────┘
```

**Por que Socket Mode:** botões interativos exigem que o Slack alcance um
endpoint. Socket Mode abre uma conexão de saída, dispensando URL pública,
ngrok ou porta aberta no roteador — essencial num lab atrás de NAT.

**Por que um bridge e não o script de integração direto:** o script do Wazuh é
processo curto e sem estado. Ele não consegue receber cliques do Slack nem
guardar o vínculo `thread_ts ↔ alert_id` que faz a thread virar nota. O bridge
é a única peça que fala com os três lados.

---

## Fluxo de uma detecção

1. Wazuh dispara regra de nível ≥ 7
2. `custom-bridge` encaminha o alerta JSON para `http://slack-iris-bridge:8000/wazuh`
3. Bridge cria o alerta no IRIS e recebe o `alert_id`
4. Bridge escolhe o template pelo `decoder.name` e posta no Slack
5. Vínculo `thread_ts ↔ alert_id` é gravado no SQLite
6. Analista age:

| Ação no Slack | Efeito no IRIS |
|---|---|
| **Assumir** | status → *Assigned*, `alert_owner_id` = usuário mapeado, entrada na nota |
| **Criar case** | abre modal com título, **template do IRIS** (se houver) e nota → escala o alerta para um case (`/alerts/escalate`), importando IOCs e assets; registra autor e link do case |
| **Fechar** | abre modal com resolução (falso positivo, legítimo, etc) e nota → status *Closed*, resolução, owner, entrada na nota, botões somem da mensagem |
| **Imagem/arquivo na thread** | é baixado do Slack e anexado como **evidência ao case** do alerta (cria o case automaticamente se ainda não existir); o bot reage com 📎 |
| **Resposta na thread** | entrada carimbada na nota; bot reage com 📥 ao sincronizar |

A nota vira o histórico cronológico do alerta:

```
[22/07/2026 21:00] — Assumido por Victor Roberto (Slack). Owner: administrator.

[22/07/2026 21:02] — Victor Roberto (Slack):
Conta criada pelo time de TI, mudança planejada.

[22/07/2026 21:05] — Fechado por Victor Roberto (Slack). Usuario IRIS: administrator.
```

---

## Formato da mensagem

```
#9 [ACTIVE DIRECTORY] [MEDIUM] - User account changed      ← link p/ Wazuh
regra 60109 · nivel 8 · decoder windows_eventchannel · agente dc01-ad · 21:02:19
───────────────────────────────────────
👤 Conta de usuario criada · EventID 4720 · canal Security
Usuario alvo: teste.link      Executado por: Administrator
🎯 MITRE: Account Manipulation (T1098)

[ Assumir ]  [ Fechar ]

Abrir no IRIS · responda nesta thread para registrar na nota do alerta
```

### Título

`#<ID do IRIS> [ORIGEM] [SEVERIDADE] - <descrição da regra>`

Todo ele é hyperlink para o Discover do Wazuh, filtrado em `agent.id`,
`rule.id` e `data.win.system.eventID` (quando existe), com janela de
±`WAZUH_WINDOW_MIN` minutos ao redor do alerta. O timestamp é convertido para
UTC antes de montar a janela.

### Rótulo de origem

| Condição | Rótulo |
|---|---|
| canal `Security` + agente em `DC_AGENTS` | `ACTIVE DIRECTORY` |
| canal `Security` + EventID exclusivo de DC (Kerberos, Directory Service) | `ACTIVE DIRECTORY` |
| canal `Security` (demais) | `WINDOWS SECURITY` |
| Sysmon / PowerShell / System / Application | `SYSMON` / `POWERSHELL` / `WINDOWS SYSTEM` / `WINDOWS APP` |
| `docker-listener`, `sshd`, `*-accesslog`, `syscheck_*` | `DOCKER`, `SSH`, `WEB`, `FIM` |
| decoder sem mapeamento | nome do decoder em maiúsculas |

### Severidade

Derivada do `rule.level`: ≥15 `CRITICAL` · ≥12 `HIGH` · ≥8 `MEDIUM` ·
≥5 `LOW` · resto `INFO`. Define também a cor da barra lateral.

---

## Configuração (`.env`)

| Variável | Padrão | Descrição |
|---|---|---|
| `SLACK_BOT_TOKEN` | — | `xoxb-...`, OAuth & Permissions |
| `SLACK_APP_TOKEN` | — | `xapp-...`, escopo `connections:write` |
| `SLACK_CHANNEL` | `#soc-alerts` | canal de destino (bot precisa estar nele) |
| `IRIS_URL_INTERNAL` | — | URL que o **container** usa para falar com o IRIS |
| `IRIS_URL_PUBLIC` | — | URL que o **analista** abre no navegador |
| `IRIS_API_KEY` | — | chave de usuário com escrita em alertas |
| `IRIS_CUSTOMER_ID` | `1` | customer do IRIS |
| `CLOSE_WITH_MODAL` | `true` | modal com resolução + nota ao fechar; `false` fecha direto |
| `IRIS_DEFAULT_RESOLUTION` | vazio | resolução aplicada quando fecha **sem** modal; vazio = não definir |
| `WAZUH_DASHBOARD_URL` | — | base do dashboard, usada nos links |
| `WAZUH_WINDOW_MIN` | `30` | janela em minutos antes/depois do alerta |
| `WAZUH_DISCOVER_ROUTE` | `data-explorer` | ou `classic` para `/app/discover` |
| `WAZUH_INDEX_PATTERN` | `wazuh-alerts-*` | index pattern do Discover |
| `DC_AGENTS` | `dc01-ad` | agentes que são Domain Controller, separados por vírgula |
| `SLACK_IRIS_USER_MAP` | `{}` | `{"U01ABC":"login_no_iris"}` quando o e-mail não bate |
| `LOG_LEVEL` | `INFO` | `DEBUG` para depurar |

### Identidade

O bridge autentica com uma API key administrativa e atribui a ação ao usuário
correto casando **e-mail do Slack com e-mail do usuário no IRIS**. Sem
correspondência, a ação é executada mesmo assim, a nota registra quem clicou e
a mensagem mostra *(não mapeado)*.

Para corrigir: pegue o member ID no Slack (perfil → ⋮ → **Copy member ID**) e
preencha `SLACK_IRIS_USER_MAP={"U01ABCDEF":"administrator"}`.

---

## Adicionar um template

Em `app/templates.py`:

```python
@template("nome_do_decoder")
def _meu_decoder(ctx):
    return [section(":zap: *Meu evento*")] + fields([
        ("Campo", ctx.d("campo")),               # lê de data.campo
        ("Usuario", ctx.win("targetUserName")),  # lê de data.win.eventdata
    ])
```

Helpers do `ctx`: `ctx.d(...)`, `ctx.win(...)`, `ctx.event_id`, `ctx.mitre`,
`ctx.full_log`, `ctx.agent_name`, `ctx.level`, `ctx.rule_id`.

Para o rótulo aparecer no título, adicione em `SOURCE_LABELS`.

Rebuild: `docker compose -f docker-compose.bridge.yml up -d --build`

Um template que lance exceção não derruba o alerta — cai no fallback genérico
e a mensagem registra qual template falhou.

---

## Operação

```powershell
# logs
docker logs -f slack-iris-bridge

# integracao no lado do Wazuh
docker exec wazuh-manager tail -30 /var/ossec/logs/integrations.log

# disparar um alerta de teste sem depender do Wazuh
docker exec slack-iris-bridge python -c "
import json,urllib.request
a={'timestamp':'2026-07-22T21:00:00.000Z','rule':{'level':9,'description':'Teste manual','id':'999'},'agent':{'id':'007','name':'dc01-ad'},'decoder':{'name':'windows_eventchannel'},'data':{'win':{'system':{'channel':'Security','eventID':'4720'},'eventdata':{'targetUserName':'teste'}}}}
r=urllib.request.urlopen(urllib.request.Request('http://localhost:8000/wazuh',json.dumps(a).encode(),{'Content-Type':'application/json'}))
print(r.read())"
```

### Diagnóstico

| Sintoma | Causa provável |
|---|---|
| Nada no Slack | alerta não atingiu nível 7, ou integração não carregada — veja `integrations.log` |
| `not_in_channel` | bot não convidado: `/invite @SOC Bridge` |
| Botão não responde | `SLACK_APP_TOKEN` inválido ou Socket Mode desligado no app |
| Thread não vira nota | faltou `channels:history`/`groups:history`, ou o app foi instalado antes do escopo (reinstale) |
| Owner sempre *(não mapeado)* | e-mail Slack ≠ e-mail IRIS → use `SLACK_IRIS_USER_MAP` |
| `Failed to resolve 'iris-nginx'` | IRIS está em outro compose/rede — use o IP do host em `IRIS_URL_INTERNAL` |
| Link do título abre Discover vazio | troque `WAZUH_DISCOVER_ROUTE` para `classic` |
| Alerta duplicado no IRIS | integração `custom-iris` antiga ainda no `ossec.conf` |
| Nota sobrescrita | leitura da nota falhou antes de gravar — veja o warning no log |

---

## Limitações conhecidas

- **Nota é read-modify-write.** O IRIS não tem endpoint de append; o bridge lê,
  concatena e regrava. Um lock cobre o processo, o que basta para um container
  só. Dois bridges no mesmo IRIS podem perder entradas.
- **API key administrativa.** Quem controla o bridge age como admin no IRIS.
  Trilha de auditoria por analista exigiria a key individual de cada um.
- **TLS não verificado** (`verify=False`), porque o lab usa certificado
  autoassinado. Em produção, monte a CA no container e ative a verificação.
- **`IRIS_URL_INTERNAL` por IP.** Se o IP do host mudar, o bridge para de criar
  alertas — o Slack continua recebendo, o IRIS não.
- **Sem retry.** Falha de rede na criação do alerta perde o evento; o Wazuh não
  reenvia. O log registra o erro.

---

## Estrutura

```
slack-iris-bridge/
├── app/
│   ├── main.py          ingest HTTP, handlers do Slack, orquestração
│   ├── templates.py     Block Kit por decoder, título, link do Wazuh
│   ├── iris_client.py   API do IRIS, lookups de status/resolução/usuários
│   └── store.py         SQLite: thread_ts ↔ alert_id, dedup de eventos
├── custom-bridge        integração instalada no Wazuh Manager
├── slack-app-manifest.yml
├── docker-compose.bridge.yml
├── Dockerfile
├── .env                 credenciais (não versionar)
└── .env.example
```
