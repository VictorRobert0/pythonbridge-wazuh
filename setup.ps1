<#
.SYNOPSIS
  Sobe o SOC Bridge (Wazuh -> DFIR-IRIS -> Slack) em um novo ambiente.

.DESCRIPTION
  1. Cria o .env a partir do .env.example (se ainda nao existir).
  2. Valida se as variaveis obrigatorias foram preenchidas.
  3. Faz build e sobe o container.
  4. Opcional: instala a integracao no Wazuh Manager (-InstallWazuh).

.EXAMPLE
  .\setup.ps1
  .\setup.ps1 -InstallWazuh -WazuhContainer wazuh-manager
#>
param(
    [switch]$InstallWazuh,
    [string]$WazuhContainer = "wazuh-manager",
    [int]$Level = 7
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "== SOC Bridge :: setup ==" -ForegroundColor Cyan

# 1. .env
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "[.env] criado a partir do .env.example." -ForegroundColor Yellow
    Write-Host "       Preencha SLACK_BOT_TOKEN, SLACK_APP_TOKEN e IRIS_API_KEY e rode de novo." -ForegroundColor Yellow
    notepad ".env"
    exit 1
}

# 2. validacao das variaveis criticas
$req = @("SLACK_BOT_TOKEN","SLACK_APP_TOKEN","IRIS_API_KEY","IRIS_URL_INTERNAL","SLACK_CHANNEL")
$envMap = @{}
Get-Content ".env" | Where-Object { $_ -match "^\s*[^#].*=" } | ForEach-Object {
    $k,$v = $_ -split "=",2
    $envMap[$k.Trim()] = $v.Trim()
}
$missing = @()
foreach ($k in $req) {
    if (-not $envMap.ContainsKey($k) -or [string]::IsNullOrWhiteSpace($envMap[$k]) -or $envMap[$k] -like "*troque*") {
        $missing += $k
    }
}
if ($missing.Count -gt 0) {
    Write-Host "[erro] preencha no .env: $($missing -join ', ')" -ForegroundColor Red
    exit 1
}
Write-Host "[.env] variaveis obrigatorias OK." -ForegroundColor Green

# 3. build + up
Write-Host "[docker] build e up..." -ForegroundColor Cyan
docker compose -f docker-compose.bridge.yml up -d --build
Start-Sleep -Seconds 3
docker logs --tail 15 slack-iris-bridge

# 4. integracao no Wazuh (opcional)
if ($InstallWazuh) {
    Write-Host "[wazuh] instalando integracao em '$WazuhContainer'..." -ForegroundColor Cyan
    docker cp custom-bridge "${WazuhContainer}:/var/ossec/integrations/custom-bridge"
    docker exec $WazuhContainer chmod 750 /var/ossec/integrations/custom-bridge
    docker exec $WazuhContainer chown root:wazuh /var/ossec/integrations/custom-bridge

    $block = @"
<ossec_config>
  <integration>
    <name>custom-bridge</name>
    <hook_url>http://slack-iris-bridge:8000/wazuh</hook_url>
    <api_key>nao-usado</api_key>
    <level>$Level</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
"@
    # adiciona o bloco no ossec.conf apenas se ainda nao existir
    $check = docker exec $WazuhContainer sh -c "grep -c 'custom-bridge' /var/ossec/etc/ossec.conf 2>/dev/null || echo 0"
    if ($check.Trim() -eq "0") {
        $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($block))
        docker exec $WazuhContainer sh -c "echo $b64 | base64 -d >> /var/ossec/etc/ossec.conf"
        docker exec $WazuhContainer /var/ossec/bin/wazuh-control restart
        Write-Host "[wazuh] integracao adicionada e manager reiniciado." -ForegroundColor Green
    } else {
        Write-Host "[wazuh] integracao ja existia no ossec.conf, nada a fazer." -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Pronto. Logs ao vivo:  docker logs -f slack-iris-bridge" -ForegroundColor Green
