# Integração Sophos Firewall (SFOS)

Duas integrações independentes, que juntas fecham o ciclo **detecção → resposta**:

| Direção | O quê | Como |
|---|---|---|
| Sophos → SOC | logs de firewall/IPS viram alertas | **Syslog** para o Wazuh (decoder + regras) |
| SOC → Sophos | botão **Banir IP** bloqueia no firewall | **API XML** do SFOS, a partir do Slack |

```
Sophos ──syslog──► Wazuh ──► bridge ──► Slack ──[Banir IP]──► API Sophos ──► SOC_Blocklist
                                                                                   │
                                                              regra DROP no topo ◄─┘
```

---

## 1. Preparar o appliance

Feito uma vez, no painel do Sophos.

### 1.1 Grupo de bloqueio

**Hosts e serviços → Grupo de Host de IP → Adicionar**

- Nome: **`SOC_Blocklist`** (deve bater com `SOPHOS_BLOCK_GROUP` no `.env`)
- Deixe vazio — o bridge popula

### 1.2 Regra de firewall que bloqueia o grupo

**Regras e políticas → Regras de firewall → Adicionar**

| Campo | Valor |
|---|---|
| Nome | `SOC_Block_Malicious` |
| Ação | **Drop** |
| **Fazer Log de Tráfego de Firewall** | **marcado** (sem isso o drop não vira syslog) |
| Zonas de origem | LAN, WAN |
| Redes de origem | **SOC_Blocklist** |
| Zonas de destino | LAN, WAN |
| Redes/Serviços de destino | Qualquer |
| **Posição** | **Topo** (antes das regras de liberação) |

### 1.3 Habilitar a API

**Sistema → Administração → API** (ou *Dispositivo de acesso*)

- Ligar **Configuração da API**
- **IP permitido:** o endereço de onde o bridge chega. No lab: `172.16.16.1`
  (o container sai pela perna do host na rede LAN do Sophos)

> Sem esse passo a API responde `Status code="532" — You need to enable the
> API Configuration`, mesmo com usuário e senha corretos.

### 1.4 Syslog para o Wazuh

**Serviços de Sistema → Ajustes de Log → Servidores Syslog → Adicionar**

| Campo | Valor |
|---|---|
| Nome | `Wazuh` |
| IP do Servidor | `172.16.16.1` |
| Porta | `514` (UDP) |
| **Severidade** | **Informação** |
| Formato | Standard syslog protocol |

Na tabela **Ajustes de Log** abaixo, marque as categorias na **coluna do seu
servidor** (não na de "Relatórios locais") — no mínimo **Regras de Firewall** e
**IPS** — e clique em **Aplicar**.

**Duas armadilhas aqui:**

- **Severidade "Emergência"** (padrão em algumas versões) descarta tudo: logs de
  firewall são *Information*, que fica abaixo do corte. Nada é enviado.
- **Endereço do servidor:** aponte para um IP na **mesma rede** do Sophos. Se o
  Wazuh estiver atrás de NAT (ex.: `192.168.18.10` via NAT do VMware), o pacote
  não chega. O IP do host na LAN do firewall resolve.

---

## 2. Wazuh: receber e interpretar

### 2.1 Escutar syslog

No `docker-compose.yml` do stack, no serviço do manager:

```yaml
    ports:
      - "514:514/udp"
```

E no `ossec.conf`:

```xml
<ossec_config>
  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>udp</protocol>
    <allowed-ips>172.16.16.0/24</allowed-ips>
  </remote>
</ossec_config>
```

```bash
docker compose up -d --force-recreate wazuh-manager
# confirmar que escuta (0202 = 514 em hex)
docker exec wazuh-manager sh -c "grep ':0202 ' /proc/net/udp && echo LISTENING-514"
```

### 2.2 Decoder e regras

O Wazuh 4.9 **não traz decoder** para o formato `key="value"` do SFOS — sem ele
os eventos chegam mas não viram alerta. Os arquivos estão em `wazuh-sophos/`:

```bash
docker cp wazuh-sophos/local_decoder.xml wazuh-manager:/var/ossec/etc/decoders/local_decoder.xml
docker cp wazuh-sophos/local_rules.xml   wazuh-manager:/var/ossec/etc/rules/local_rules.xml
docker exec wazuh-manager /var/ossec/bin/wazuh-control restart
```

| Regra | Nível | O quê |
|---|---|---|
| `100210` | 8 | tráfego **bloqueado** (Denied/Drop) → vira card no Slack |
| `100201` | 0 | broadcast NetBIOS/mDNS/SSDP (137/138/5353/1900) → **silenciado** |
| `100220` | 10 | detecção de **IPS / ATP / Anti-Virus** |

> `dstport` é campo **estático** no Wazuh e não pode ser usado em `<field>`.
> Por isso a porta é decodificada como `sophos.dstport`.

### 2.3 Validar

```bash
docker exec -i wazuh-manager /var/ossec/bin/wazuh-logtest
```

Cole uma linha real do Sophos. Esperado: **Phase 2** com `name: 'sophos-fw'` e
os campos `srcip`, `dstip`, `sophos.dstport`, `sophos.action`; **Phase 3** com a
regra correspondente.

---

## 3. Bridge: botão Banir IP

No `.env`:

```
SOPHOS_URL=https://172.16.16.16:4444
SOPHOS_USER=admin
SOPHOS_PASS=...
SOPHOS_BLOCK_GROUP=SOC_Blocklist
SOPHOS_VERIFY_TLS=false
```

O botão **só aparece** quando as três primeiras variáveis estão preenchidas
**e** o alerta é do Sophos (decoder `sophos*` ou grupo de regra contendo
`sophos`). Alertas de AD, SSH ou Docker não mostram o botão — bloquear IP no
perímetro só faz sentido para evento de rede.

No boot, confirme no log:

```
Sophos habilitado — botao 'Banir IP' ativo (grupo SOC_Blocklist)
```

### O que o clique faz

1. Abre uma **confirmação** com o IP e um campo de motivo (ação destrutiva).
2. Cria um IP Host `SOC_Ban_<ip>` no Sophos.
3. Adiciona esse host ao grupo `SOC_Blocklist`, preservando os existentes.
4. Registra na **nota do alerta no IRIS** (quem baniu, quando, motivo) e na
   mensagem do Slack.

Idempotente: se o IP já estiver na blocklist, responde "já estava bloqueado"
sem erro.

### Conferir no Sophos

- **Hosts e serviços → Host de IP** → aparece `SOC_Ban_<ip>`
- **Grupo de Host de IP → SOC_Blocklist** → o host está na lista

---

## Diagnóstico

| Sintoma | Causa |
|---|---|
| `532 — You need to enable the API Configuration` | API desligada (1.3) |
| `Authentication Failure` | usuário/senha errados, ou perfil sem permissão |
| `Grupo 'X' nao encontrado. Grupos encontrados: ...` | `SOPHOS_BLOCK_GROUP` não bate — use um dos listados |
| Botão **Banir IP** não aparece | `SOPHOS_*` vazio no `.env`, ou o alerta não é do Sophos |
| Syslog não chega | severidade em "Emergência", coluna do servidor desmarcada, faltou **Aplicar**, ou IP atrás de NAT |
| Chega no `archives` mas não vira alerta | falta o decoder (2.2) |
| Só aparecem eventos NetBIOS | o Sophos **não loga tráfego permitido** — só drops; ligue o log na regra |
| Nada após mudar config | o serviço de log do SFOS às vezes precisa de **Aplicar** ou reinício do appliance |

Ver o que está chegando:

```bash
docker exec wazuh-manager sh -c "grep SophosFirewall /var/ossec/logs/archives/archives.log | tail -3"
docker exec wazuh-manager sh -c "grep -E '100210|100220' /var/ossec/logs/alerts/alerts.log | tail -5"
```

> O `archives.log` só grava com `<logall>yes</logall>` — útil para depurar,
> mas **desligue depois**: ele grava todo evento recebido, inclusive o ruído do
> docker-listener.

---

## Limitações

- **A API do SFOS é sensível à versão.** O cliente lista todos os IP Host Groups
  e casa pelo nome, em vez de usar filtro no `<Get>` (que não é aceito em
  2200.x). Se mudar de versão, valide `block_ip` antes de confiar.
- **Sem desbanir pelo Slack.** Remover um IP da blocklist é manual, no painel.
- **`SOPHOS_VERIFY_TLS=false`** por causa do certificado autoassinado; em
  produção, monte a CA e ative.
- **A senha vai no `.env`.** Em produção use os Docker secrets já preparados no
  `docker-compose.prod.yml` (`SOPHOS_PASS_FILE`).
