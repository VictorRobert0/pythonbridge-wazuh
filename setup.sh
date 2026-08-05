#!/usr/bin/env bash
# Sobe o SOC Bridge (Wazuh -> DFIR-IRIS -> Slack) em um novo ambiente.
#
#   ./setup.sh                          # build + up
#   ./setup.sh --install-wazuh          # tambem instala a integracao no manager
#   WAZUH_CONTAINER=wazuh-manager LEVEL=7 ./setup.sh --install-wazuh
set -euo pipefail
cd "$(dirname "$0")"

INSTALL_WAZUH=0
[ "${1:-}" = "--install-wazuh" ] && INSTALL_WAZUH=1
WAZUH_CONTAINER="${WAZUH_CONTAINER:-wazuh-manager}"
LEVEL="${LEVEL:-7}"

echo "== SOC Bridge :: setup =="

# 1. .env
if [ ! -f .env ]; then
  cp .env.example .env
  echo "[.env] criado a partir do .env.example."
  echo "       Preencha SLACK_BOT_TOKEN, SLACK_APP_TOKEN e IRIS_API_KEY e rode de novo."
  exit 1
fi

# 2. validacao
missing=()
for k in SLACK_BOT_TOKEN SLACK_APP_TOKEN IRIS_API_KEY IRIS_URL_INTERNAL SLACK_CHANNEL; do
  v=$(grep -E "^\s*${k}=" .env | head -1 | cut -d= -f2- | tr -d ' ' || true)
  if [ -z "$v" ] || echo "$v" | grep -qi troque; then missing+=("$k"); fi
done
if [ "${#missing[@]}" -gt 0 ]; then
  echo "[erro] preencha no .env: ${missing[*]}"; exit 1
fi
echo "[.env] variaveis obrigatorias OK."

# 3. build + up
echo "[docker] build e up..."
docker compose -f docker-compose.bridge.yml up -d --build
sleep 3
docker logs --tail 15 slack-iris-bridge || true

# 4. integracao no Wazuh (opcional)
if [ "$INSTALL_WAZUH" = "1" ]; then
  echo "[wazuh] instalando integracao em '$WAZUH_CONTAINER'..."
  docker cp custom-bridge "${WAZUH_CONTAINER}:/var/ossec/integrations/custom-bridge"
  docker exec "$WAZUH_CONTAINER" chmod 750 /var/ossec/integrations/custom-bridge
  docker exec "$WAZUH_CONTAINER" chown root:wazuh /var/ossec/integrations/custom-bridge
  if [ "$(docker exec "$WAZUH_CONTAINER" sh -c "grep -c custom-bridge /var/ossec/etc/ossec.conf || echo 0")" = "0" ]; then
    docker exec "$WAZUH_CONTAINER" sh -c "cat >> /var/ossec/etc/ossec.conf" <<EOF
<ossec_config>
  <integration>
    <name>custom-bridge</name>
    <hook_url>http://slack-iris-bridge:8000/wazuh</hook_url>
    <api_key>nao-usado</api_key>
    <level>${LEVEL}</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
EOF
    docker exec "$WAZUH_CONTAINER" /var/ossec/bin/wazuh-control restart
    echo "[wazuh] integracao adicionada e manager reiniciado."
  else
    echo "[wazuh] integracao ja existia, nada a fazer."
  fi
fi

echo ""
echo "Pronto. Logs:  docker logs -f slack-iris-bridge"
