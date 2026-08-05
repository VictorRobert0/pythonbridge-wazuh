# Runbook — Replicar o SOC Lab do zero

Guia para reconstruir o ambiente completo: Active Directory monitorado pelo
Wazuh, alertas criando casos no DFIR-IRIS e chegando no Slack com botões que
funcionam.

Cada fase termina com uma **validação**. Não avance sem ela passar — a maior
parte do tempo perdido em ambientes assim vem de seguir adiante com uma peça
meio configurada.

---

## Índice

1. [Pré-requisitos](#1-pré-requisitos)
2. [Rede e VM do Windows Server](#2-rede-e-vm-do-windows-server)
3. [Active Directory](#3-active-directory)
4. [Ingressar estações no domínio](#4-ingressar-estações-no-domínio)
5. [Estrutura do AD e políticas](#5-estrutura-do-ad-e-políticas)
6. [Agente Wazuh no Domain Controller](#6-agente-wazuh-no-domain-controller)
7. [Docker Listener no Wazuh](#7-docker-listener-no-wazuh)
8. [App do Slack](#8-app-do-slack)
9. [Bridge Wazuh → IRIS → Slack](#9-bridge-wazuh--iris--slack)
10. [Validação ponta a ponta](#10-validação-ponta-a-ponta)
11. [Armadilhas conhecidas](#11-armadilhas-conhecidas)
12. [Adaptar para outro ambiente](#12-adaptar-para-outro-ambiente)

---

## 1. Pré-requisitos

| Item | Versão de referência |
|---|---|
| Host | Windows com Docker Desktop |
| VMware Workstation | qualquer versão com modo Bridged |
| Windows Server | 2022 |
| Estação cliente | Windows 10/11 **Pro** ou Enterprise (Home não ingressa em domínio) |
| Wazuh | 4.9.0 (manager e agentes na **mesma** versão) |
| DFIR-IRIS | v2.4.27 |
| Workspace do Slack | com permissão para criar apps |

Stack do lab já em pé via Docker Compose: `wazuh-manager`, `wazuh-indexer`,
`wazuh-dashboard`, IRIS (`iris-web`, `iris-db`, nginx), MISP, Velociraptor.

**Endereços usados neste guia** — troque pelos seus:

| Serviço | Endereço |
|---|---|
| Host Docker | `192.168.18.10` |
| Gateway | `192.168.18.1` |
| Domain Controller | `192.168.18.100` |
| Wazuh Dashboard | `https://192.168.18.10:4443` |
| DFIR-IRIS | `https://192.168.18.10` |
| Rede Docker | `soc-lab_soc-net` |

---

## 2. Rede e VM do Windows Server

### 2.1 Adaptador em modo Bridged

Na VM do Windows Server: **Settings → Network Adapter → Bridged**, com
*Replicate physical network connection state* marcado.

> **Crítico:** se o host tem vários adaptadores virtuais (Hyper-V, WSL, VMnet1,
> VMnet8), o modo *Automatic* frequentemente faz bridge no adaptador errado e
> nada se comunica.

**Edit → Virtual Network Editor → Change Settings** → selecione **VMnet0
(Bridged)** e escolha **manualmente** o adaptador físico da máquina (o de
1 Gbps, não os virtuais).

### 2.2 IP fixo no servidor

```powershell
Get-NetAdapter   # descubra o nome, normalmente "Ethernet0"

# remova IPs de outras subnets, se houver
Get-NetIPAddress -InterfaceAlias "Ethernet0" -AddressFamily IPv4

New-NetIPAddress -InterfaceAlias "Ethernet0" -IPAddress 192.168.18.100 `
  -PrefixLength 24 -DefaultGateway 192.168.18.1

Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False  # lab apenas
```

### ✅ Validação

```powershell
ping 192.168.18.1        # do servidor para o gateway
```

E de outra máquina da rede: `ping 192.168.18.100`. **Os dois precisam
responder** antes de seguir.

---

## 3. Active Directory

### 3.1 Escolha do nome do domínio

**Não use `.local`.** O Windows 11 intercepta esse TLD para mDNS e as consultas
nunca chegam ao DNS do domínio — o ingresso falha com *"O domínio especificado
não existe ou não pôde ser contatado"* mesmo com tudo correto.

Use `.corp`, `.lan`, `.internal` ou um subdomínio de domínio próprio.

### 3.2 Instalar e promover

```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

Install-ADDSForest -DomainName "soclab.corp" -DomainNetbiosName "SOCLAB" -InstallDns:$true -SafeModeAdministratorPassword (ConvertTo-SecureString "SuaSenhaForte123!" -AsPlainText -Force) -Force:$true
```

Comando em **linha única** — backticks costumam quebrar ao colar no console da VM.

O servidor reinicia sozinho.

### ✅ Validação

```powershell
Get-ADDomainController
Get-DnsServerZone            # deve listar soclab.corp e _msdcs.soclab.corp
Resolve-DnsName soclab.corp  # deve resolver para 192.168.18.100
```

### Se precisar refazer o domínio

```powershell
# rebaixar (ultimo DC da floresta)
Uninstall-ADDSDomainController -LastDomainControllerInDomain -RemoveApplicationPartitions -LocalAdministratorPassword (ConvertTo-SecureString "SuaSenhaForte123!" -AsPlainText -Force) -Force
```

Não combine `-ForceRemoval` com `-LastDomainControllerInDomain` — os
parameter sets conflitam e o comando falha.

---

## 4. Ingressar estações no domínio

Na estação, **PowerShell como Administrador**:

```powershell
Get-NetAdapter    # descubra o nome: "Wi-Fi", "Ethernet"...

Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses 192.168.18.100
```

### O IPv6 do roteador atrapalha

Mesmo com o DNS IPv4 correto, o Windows consulta primeiro o **DNS IPv6**
anunciado pelo roteador (`fe80::1`), que responde *"não existe"* e encerra a
resolução. Sintoma clássico: `nslookup dominio 192.168.18.100` funciona, mas
`Resolve-DnsName dominio` falha.

```powershell
# confirme o diagnostico — se "Servidor" for um endereco IPv6, e isso
nslookup soclab.corp

# desabilite IPv6 no adaptador
Disable-NetAdapterBinding -Name "Wi-Fi" -ComponentID ms_tcpip6
Clear-DnsClientCache
```

### Ingressar

```powershell
Resolve-DnsName soclab.corp     # precisa resolver ANTES de tentar
Add-Computer -DomainName "soclab.corp" -Credential (Get-Credential) -Restart
```

Credenciais: `SOCLAB\Administrator`.

### ✅ Validação

O PC reinicia sozinho. Na tela de login, **Outro usuário** → entre com
`SOCLAB\Administrator`. Abaixo do campo de senha deve aparecer
*"Entrar em: SOCLAB"*.

---

## 5. Estrutura do AD e políticas

### 5.1 OUs, grupos e usuários

```powershell
New-ADOrganizationalUnit -Name "SOCLAB-Empresa" -Path "DC=soclab,DC=corp"
$base = "OU=SOCLAB-Empresa,DC=soclab,DC=corp"

foreach ($ou in "TI","RH","Financeiro","Diretoria","Computadores") {
    New-ADOrganizationalUnit -Name $ou -Path $base
}

New-ADGroup -Name "GRP-TI-Admins"   -GroupScope Global -GroupCategory Security -Path "OU=TI,$base"
New-ADGroup -Name "GRP-TI-Suporte"  -GroupScope Global -GroupCategory Security -Path "OU=TI,$base"
New-ADGroup -Name "GRP-RH"          -GroupScope Global -GroupCategory Security -Path "OU=RH,$base"
New-ADGroup -Name "GRP-Financeiro"  -GroupScope Global -GroupCategory Security -Path "OU=Financeiro,$base"
New-ADGroup -Name "GRP-Diretoria"   -GroupScope Global -GroupCategory Security -Path "OU=Diretoria,$base"

$senha = ConvertTo-SecureString "Soclab@2026!" -AsPlainText -Force
New-ADUser -Name "Carlos Silva" -SamAccountName "carlos.silva" -UserPrincipalName "carlos.silva@soclab.corp" -Path "OU=TI,$base" -AccountPassword $senha -Enabled $true -Department "TI"
New-ADUser -Name "Ana Souza"    -SamAccountName "ana.souza"    -UserPrincipalName "ana.souza@soclab.corp"    -Path "OU=TI,$base" -AccountPassword $senha -Enabled $true -Department "TI"
New-ADUser -Name "Beatriz Lima" -SamAccountName "beatriz.lima" -UserPrincipalName "beatriz.lima@soclab.corp" -Path "OU=RH,$base" -AccountPassword $senha -Enabled $true -Department "RH"

Add-ADGroupMember -Identity "GRP-TI-Admins"  -Members "carlos.silva"
Add-ADGroupMember -Identity "GRP-TI-Suporte" -Members "ana.souza"
Add-ADGroupMember -Identity "GRP-RH"         -Members "beatriz.lima"
```

Os usuários ficam visíveis no **Active Directory Users and Computers**
(`dsa.msc`), não no Server Manager.

### 5.2 Política de senha e bloqueio

```powershell
Set-ADDefaultDomainPasswordPolicy -Identity soclab.corp -ComplexityEnabled $true -MinPasswordLength 12 -MaxPasswordAge "90.00:00:00" -MinPasswordAge "1.00:00:00" -PasswordHistoryCount 12
Set-ADDefaultDomainPasswordPolicy -Identity soclab.corp -LockoutThreshold 5 -LockoutDuration "00:15:00" -LockoutObservationWindow "00:15:00"
```

### 5.3 Auditoria — essencial para o Wazuh ver alguma coisa

```powershell
New-GPO -Name "GPO-Auditoria-Logon" | New-GPLink -Target "DC=soclab,DC=corp"
```

Em **Group Policy Management** → edite a GPO → **Computer Configuration →
Policies → Windows Settings → Security Settings → Local Policies → Audit
Policy** → habilite **Success e Failure** em:

- Audit account logon events
- Audit logon events
- Audit account management

```powershell
gpupdate /force
```

### ✅ Validação

```powershell
Get-ADUser -Filter * -SearchBase $base | Select-Object Name, SamAccountName
Get-ADDefaultDomainPasswordPolicy
```

Gere um evento e confirme no Event Viewer (canal Security, ID 4720):

```powershell
New-ADUser -Name "Teste Auditoria" -SamAccountName "teste.audit" -AccountPassword $senha -Enabled $true
```

---

## 6. Agente Wazuh no Domain Controller

A versão do agente **precisa ser igual ou anterior** à do manager — o manager
rejeita agentes mais novos.

```powershell
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.0-1.msi" -OutFile "$env:TEMP\wazuh-agent.msi"

msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q WAZUH_MANAGER="192.168.18.10" WAZUH_AGENT_NAME="dc01-ad" WAZUH_REGISTRATION_SERVER="192.168.18.10"

Start-Sleep -Seconds 30
Start-Service WazuhSvc
Get-Service WazuhSvc
```

### ✅ Validação

No host:

```powershell
docker exec -it wazuh-manager /var/ossec/bin/manage_agents -l
```

O agente `dc01-ad` deve aparecer. No dashboard, o status precisa estar
**Active** — se ficar *Disconnected*, teste a porta:

```powershell
Test-NetConnection -ComputerName 192.168.18.10 -Port 1514
```

> **Agentes em container** não têm systemd. Após reiniciar o container:
> `docker exec <nome> /var/ossec/bin/wazuh-control start`

---

## 7. Docker Listener no Wazuh

Monitora eventos do próprio Docker (containers criados, parados, redes).

**1. Dependência Python no manager:**

```powershell
docker exec wazuh-manager /var/ossec/framework/python/bin/pip3 install docker==7.1.0
```

**2. Socket do Docker no container** — em `docker-compose.yml`, no bloco
`volumes:` do serviço do manager:

```yaml
      - //var/run/docker.sock:/var/run/docker.sock
```

A barra dupla inicial é necessária no Docker Desktop para Windows.

**3. Habilitar o módulo:**

```powershell
docker exec -it wazuh-manager bash
```

```bash
cat >> /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <wodle name="docker-listener">
    <interval>10m</interval>
    <attempts>5</attempts>
    <run_on_start>yes</run_on_start>
    <disabled>no</disabled>
  </wodle>
</ossec_config>
EOF
/var/ossec/bin/wazuh-control restart
exit
```

```powershell
docker compose up -d wazuh-manager
```

### ✅ Validação

```powershell
docker exec wazuh-manager ls -la /var/run/docker.sock
docker exec wazuh-manager grep -i docker-listener /var/ossec/logs/ossec.log | tail -5
```

Espere `Module docker-listener started` e `Starting to listening Docker events`.

---

## 8. App do Slack

1. <https://api.slack.com/apps> → **Create New App** → **From an app manifest**
2. Escolha o workspace e cole `slack-app-manifest.yml`
3. **Create** → **Install to Workspace** → **Allow**
4. **Basic Information** → **App-Level Tokens** → **Generate Token and Scopes**
   - nome `socket`, escopo `connections:write` → copie o `xapp-...`
5. **OAuth & Permissions** → copie o **Bot User OAuth Token** `xoxb-...`
6. No Slack: crie `#soc-alerts` e rode `/invite @SOC Bridge`

> **Incoming Webhook não serve.** Ele só posta, em mão única — não recebe
> cliques de botão nem lê threads. É preciso o app com Socket Mode.

### Escopos e para que servem

| Escopo | Uso |
|---|---|
| `chat:write` | postar e editar os alertas |
| `channels:history`, `groups:history` | ler respostas em thread |
| `reactions:write` | marcar a mensagem sincronizada com 📥 |
| `users:read`, `users:read.email` | casar usuário do Slack com usuário do IRIS |

Se adicionar escopo depois, **reinstale o app** — escopos novos não valem
retroativamente.

---

## 9. Bridge Wazuh → IRIS → Slack

### 9.1 API key do IRIS

<https://192.168.18.10> → canto superior direito → **My settings** →
**API Key**. Use um usuário com escrita em alertas.

### 9.2 Configurar

```powershell
cd C:\caminho\para\soc-lab\slack-iris-bridge
copy .env.example .env
notepad .env
```

Preencha `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`, `IRIS_API_KEY`.

**`IRIS_URL_INTERNAL`** é o ponto onde mais se erra. O bridge precisa alcançar
o IRIS *de dentro da rede Docker*:

- IRIS no **mesmo** compose → use o nome do container (ex: `https://iris-nginx`)
- IRIS em **outro** compose/rede → use o IP do host (`https://192.168.18.10`)

Confirme antes:

```powershell
docker inspect <container-do-iris> --format "{{json .NetworkSettings.Networks}}"
docker network ls | Select-String soc
```

### 9.3 Subir

Confira o nome da rede no fim de `docker-compose.bridge.yml`
(`name: soc-lab_soc-net`) e:

```powershell
docker compose -f docker-compose.bridge.yml up -d --build
docker logs -f slack-iris-bridge
```

Esperado:

```
Status carregados: {'new': 2, 'assigned': 3, 'closed': 6, ...}
Resolucoes carregadas: {'false positive': 1, ...}
Usuarios IRIS carregados: N
Ingest HTTP escutando em 0.0.0.0:8000
⚡️ Bolt app is running!
```

Os três primeiros confirmam o IRIS; o último, o Slack.

### 9.4 Ligar o Wazuh ao bridge

```powershell
docker cp custom-bridge wazuh-manager:/var/ossec/integrations/custom-bridge
docker exec wazuh-manager chmod 750 /var/ossec/integrations/custom-bridge
docker exec wazuh-manager chown root:wazuh /var/ossec/integrations/custom-bridge
docker exec -it wazuh-manager bash
```

```bash
cat >> /var/ossec/etc/ossec.conf << 'EOF'
<ossec_config>
  <integration>
    <name>custom-bridge</name>
    <hook_url>http://slack-iris-bridge:8000/wazuh</hook_url>
    <api_key>nao-usado</api_key>
    <level>7</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
EOF
/var/ossec/bin/wazuh-control restart
exit
```

O `<level>` controla o volume. 7 já é bastante conversa; 10 ou 12 deixa só o
que importa.

### 9.5 Mapear seu usuário

Perfil no Slack → ⋮ → **Copy member ID** (começa com `U`). No `.env`:

```
SLACK_IRIS_USER_MAP={"U01ABCDEF":"administrator"}
```

Só é necessário quando o e-mail do Slack difere do e-mail no IRIS.

---

## 10. Validação ponta a ponta

No **DC01**:

```powershell
# 1. criacao de conta -> evento 4720
New-ADUser -Name "Teste Pipeline" -SamAccountName "teste.pipeline" -AccountPassword (ConvertTo-SecureString "Teste@2026!" -AsPlainText -Force) -Enabled $true

# 2. escalacao de privilegio -> evento 4728, com destaque no template
Add-ADGroupMember -Identity "Domain Admins" -Members "teste.pipeline"
```

Percorra a cadeia:

| # | Onde | O que esperar |
|---|---|---|
| 1 | `docker exec wazuh-manager tail -20 /var/ossec/logs/alerts/alerts.log` | alerta com `rule.id` e `agent.name: dc01-ad` |
| 2 | `docker exec wazuh-manager tail -20 /var/ossec/logs/integrations.log` | `custom-bridge: ok alert_id=N` |
| 3 | `docker logs --tail 20 slack-iris-bridge` | `Alerta IRIS #N postado no Slack` |
| 4 | IRIS → **Alerts** | alerta com título, IOCs e asset |
| 5 | Slack `#soc-alerts` | card com título `#N [ACTIVE DIRECTORY] [...]` |

Depois teste as interações:

- **clique no título** → abre o Discover do Wazuh já filtrado no agente, regra e janela de tempo
- **Assumir** → IRIS muda para *Assigned*, entrada aparece no Alert note
- **responda na thread** → texto entra no Alert note com carimbo e autor; bot reage com 📥
- **Fechar** → IRIS vai para *Closed*, botões somem do card

---

## 11. Armadilhas conhecidas

| Sintoma | Causa | Correção |
|---|---|---|
| VM não pinga o gateway | VMware Bridged em *Automatic* com muitos adaptadores virtuais | Virtual Network Editor → VMnet0 → escolher o adaptador físico manualmente |
| `Destination host unreachable` da rede para a VM | mesma causa | idem |
| IP de subnet errada na VM | IP legado de outra configuração | `Remove-NetIPAddress -IPAddress <ip>` |
| Ingresso falha com `.local` | Windows 11 intercepta `.local` para mDNS | recriar o domínio com `.corp`/`.lan` |
| `nslookup` funciona, `Resolve-DnsName` falha | DNS IPv6 do roteador (`fe80::1`) responde antes | `Disable-NetAdapterBinding -ComponentID ms_tcpip6` |
| `Uninstall-ADDSDomainController` — *parameter set cannot be resolved* | `-ForceRemoval` junto de `-LastDomainControllerInDomain` | usar só `-LastDomainControllerInDomain` |
| `Install-ADDSForest` — *DomainNetbiosName não reconhecido* | grafia (`DomainNetBIOSName`) e backticks quebrados ao colar | `-DomainNetbiosName`, comando em linha única |
| Agente Wazuh rejeitado | agente mais novo que o manager | fixar a versão do agente na do manager |
| Agente em container cai após restart | sem systemd no container | `docker exec <c> /var/ossec/bin/wazuh-control start` |
| `netdom` não existe | não vem no Windows 11 | usar `Add-Computer` ou `sysdm.cpl` |
| Bridge: `Failed to resolve 'iris-nginx'` | IRIS em outro compose/rede | `IRIS_URL_INTERNAL` com o IP do host |
| Botão do Slack não faz nada | Webhook em vez de app, ou Socket Mode desligado | criar o app pelo manifesto |
| Duas linhas de título no Slack | `text` enviado junto de `attachments` | fallback dentro do attachment, sem `text` |
| Alerta duplicado no IRIS | duas integrações ativas no `ossec.conf` | remover o bloco antigo |

---

## 12. Adaptar para outro ambiente

Para reaproveitar em outro cliente ou laboratório, troque:

**Endereços** — `.env` (`IRIS_URL_*`, `WAZUH_DASHBOARD_URL`) e o `hook_url` da
integração no `ossec.conf`.

**Domínio** — nome, OUs, grupos e usuários na seção 5. Ajuste `DC_AGENTS` no
`.env` com o nome do agente do DC (`DC_AGENTS=dc01,dc02` para múltiplos).

**Rede Docker** — `name:` no fim de `docker-compose.bridge.yml`.

**Canal do Slack** — `SLACK_CHANNEL`, e convide o bot no canal novo.

**Templates** — `app/templates.py`. Adicione decoders conforme as fontes do
ambiente (Sysmon, Suricata, Office 365, o que houver).

**Volume de alertas** — `<level>` na integração.

### Checklist rápido

```
[ ] Bridged no adaptador físico correto
[ ] Ping bidirecional entre host e servidor
[ ] Domínio SEM .local
[ ] IPv6 desabilitado nas estações (ou DNS IPv6 apontando para o DC)
[ ] Auditoria habilitada por GPO (Success + Failure)
[ ] Agente Wazuh na mesma versão do manager, status Active
[ ] App do Slack criado pelo manifesto, bot convidado no canal
[ ] IRIS_URL_INTERNAL alcançável de dentro do container
[ ] Log do bridge com "Status carregados" e "Bolt app is running"
[ ] Teste ponta a ponta: 4720 e 4728 percorrendo as 5 etapas
```
