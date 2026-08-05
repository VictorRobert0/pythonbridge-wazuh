#!/usr/bin/env python3
"""Diagnostico da integracao com o Sophos Firewall.

Roda DENTRO do container do bridge (tem rede e credenciais):

    docker exec slack-iris-bridge python /srv/app/../tools/sophos_diag.py
    docker exec slack-iris-bridge python /srv/tools/sophos_diag.py

Mostra, direto da API do appliance:
  1. se a API responde e autentica
  2. a configuracao de servidores syslog (o que o Sophos acha que deve enviar)
  3. o conteudo do grupo de bloqueio
  4. opcionalmente, envia um syslog de teste para o destino configurado
"""

import re
import sys

sys.path.insert(0, "/srv/app")

from config import settings          # noqa: E402
from sophos_client import SophosClient, SophosError  # noqa: E402


def secao(t):
    print("\n" + "=" * 70)
    print(t)
    print("=" * 70)


def main():
    if not settings.SOPHOS_ENABLED:
        print("SOPHOS_* nao configurado no .env — nada a diagnosticar.")
        return 1

    c = SophosClient(settings.SOPHOS_URL, settings.SOPHOS_USER,
                     settings.SOPHOS_PASS,
                     block_group=settings.SOPHOS_BLOCK_GROUP,
                     verify_ssl=settings.resolve_verify())

    secao("1. API do Sophos")
    print("URL: {}  usuario: {}".format(settings.SOPHOS_URL, settings.SOPHOS_USER))
    try:
        c._call("<Get><IPHostGroup></IPHostGroup></Get>")
        print("OK — API habilitada e autenticada.")
    except SophosError as e:
        print("FALHOU: {}".format(e))
        print("\n-> 532 = habilite Sistema > Administracao > API")
        print("-> Authentication Failure = usuario/senha ou perfil sem permissao")
        return 1

    secao("2. Servidores syslog configurados no appliance")
    achou_syslog = False
    for entidade in ("SyslogServers", "Syslog"):
        try:
            xml = c._call("<Get><{0}></{0}></Get>".format(entidade))
        except SophosError:
            continue
        if "<Status" in xml and "No. of records Zero" in xml:
            continue
        blocos = re.findall(r"<{0}[^>]*>(.*?)</{0}>".format(entidade), xml, re.S | re.I)
        for b in blocos:
            achou_syslog = True
            def campo(nome, texto=b):
                m = re.search(r"<{0}>\s*([^<]*)\s*</{0}>".format(nome), texto, re.I)
                return m.group(1).strip() if m else "-"
            print("  Nome:       {}".format(campo("Name")))
            print("  Servidor:   {}:{}  ({})".format(
                campo("ServerAddress"), campo("Port"), campo("Transport") or "UDP"))
            print("  Severidade: {}".format(campo("Severity")))
            print("  Facility:   {}".format(campo("Facility")))
            print("  Formato:    {}".format(campo("Format")))
            print("  Ativo:      {}".format(campo("Status") or campo("Enable")))
            print("  " + "-" * 60)
        if achou_syslog:
            break
    if not achou_syslog:
        print("  Nenhum servidor syslog retornado pela API.")
        print("  -> Configure em Servicos de Sistema > Ajustes de Log > Servidores Syslog")

    secao("3. Grupo de bloqueio ({})".format(settings.SOPHOS_BLOCK_GROUP))
    try:
        hosts, existe = c._group_hosts()
        if existe:
            print("  Grupo encontrado. Membros ({}):".format(len(hosts)))
            for h in hosts:
                print("    - {}".format(h))
            if not hosts:
                print("    (vazio)")
        else:
            print("  NAO encontrado. Grupos existentes: {}".format(
                ", ".join(c.group_names()) or "(nenhum)"))
    except SophosError as e:
        print("  Erro: {}".format(e))

    secao("Resumo")
    print("Se o item 2 mostrar o servidor correto (IP na mesma rede do Sophos,")
    print("severidade 'Information') e mesmo assim nada chegar no Wazuh:")
    print("  - reaplique as categorias em Ajustes de Log (botao Aplicar)")
    print("  - ou reinicie o appliance (o servico de log do SFOS trava as vezes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
