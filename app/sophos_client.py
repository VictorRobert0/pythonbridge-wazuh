"""Cliente da API XML do Sophos Firewall (SFOS).

Bane um IP adicionando-o a um IP Host Group ja referenciado por uma regra de
firewall DROP (criada uma vez no painel). O fluxo:

  1. cria um IP Host  'SOC_Ban_<ip>'  (idempotente)
  2. le a lista atual do grupo de bloqueio
  3. regrava o grupo incluindo o novo host

A API do SFOS e um POST em /webconsole/APIController com o campo 'reqxml'
contendo o XML; a autenticacao vai dentro do proprio XML.

O formato exato varia entre versoes do SFOS. As respostas cruas sao devolvidas
nas excecoes para facilitar o ajuste (mesmo padrao usado com o IRIS).
"""

import ipaddress
import logging
import re

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger("sophos")


class SophosError(RuntimeError):
    pass


class SophosClient:
    def __init__(self, base_url, username, password,
                 block_group="SOC_Blocklist", verify_ssl=False, timeout=30):
        self.base = base_url.rstrip("/")
        self.user = username
        self.password = password
        self.group = block_group
        self.verify = verify_ssl
        self.timeout = timeout

    # ---------- infra ----------

    def _login_xml(self):
        return "<Login><Username>{}</Username><Password>{}</Password></Login>".format(
            _xml_escape(self.user), _xml_escape(self.password))

    def _call(self, inner_xml):
        reqxml = "<Request>{}{}</Request>".format(self._login_xml(), inner_xml)
        url = self.base + "/webconsole/APIController"
        r = requests.post(url, data={"reqxml": reqxml},
                          verify=self.verify, timeout=self.timeout)
        if r.status_code >= 400:
            raise SophosError("HTTP {} do Sophos: {}".format(r.status_code, r.text[:300]))
        text = r.text
        # erro de autenticacao vem como <Login><status>Authentication Failure</status>
        if re.search(r"Authentication Failure", text, re.I):
            raise SophosError("Autenticacao falhou no Sophos (usuario/senha).")
        return text

    @staticmethod
    def _status_ok(text, entity):
        """True se a operacao sobre <entity> teve sucesso (code 200/216)."""
        # <entity><Status code="200">Configuration applied successfully.</Status>
        m = re.search(
            r"<{0}[^>]*>.*?<Status[^>]*code=\"(\d+)\"".format(entity),
            text, re.S | re.I)
        if m:
            code = m.group(1)
            return code in ("200", "216", "217")  # ok / already exists variants
        # algumas versoes retornam <Status>Configuration applied successfully.</Status>
        return bool(re.search(r"successfully", text, re.I))

    # ---------- operacoes ----------

    def _add_iphost(self, name, ip):
        inner = (
            "<Set operation=\"add\">"
            "<IPHost><Name>{}</Name><IPFamily>IPv4</IPFamily>"
            "<HostType>IP</HostType><IPAddress>{}</IPAddress></IPHost>"
            "</Set>"
        ).format(_xml_escape(name), ip)
        text = self._call(inner)
        # 'already exists' tambem serve para o nosso proposito
        if self._status_ok(text, "IPHost") or re.search(r"already exist", text, re.I):
            return text
        raise SophosError("Falha ao criar IP Host no Sophos: {}".format(text[:400]))

    def _all_groups(self):
        """[(nome, bloco_xml)] de todos os IP Host Groups do Sophos."""
        text = self._call("<Get><IPHostGroup></IPHostGroup></Get>")
        self._last_raw = text[:3000]
        out = []
        for bloco in re.findall(r"<IPHostGroup[^>]*>(.*?)</IPHostGroup>",
                                text, re.S | re.I):
            m = re.search(r"<Name>\s*([^<]+?)\s*</Name>", bloco, re.I)
            if m:
                out.append((m.group(1).strip(), bloco))
        return out

    def group_names(self):
        return [n for n, _ in self._all_groups()]

    def _group_hosts(self):
        """(hosts, existe) do grupo de bloqueio, casando o nome sem case."""
        alvo = self.group.strip().lower()
        for nome, bloco in self._all_groups():
            if nome.strip().lower() == alvo:
                hosts = re.findall(r"<Host>\s*([^<]+?)\s*</Host>", bloco, re.S)
                return [h.strip() for h in hosts if h.strip()], True
        return [], False

    def _set_group(self, hosts):
        host_xml = "".join("<Host>{}</Host>".format(_xml_escape(h)) for h in hosts)
        inner = (
            "<Set operation=\"update\"><IPHostGroup><Name>{}</Name>"
            "<IPFamily>IPv4</IPFamily><HostList>{}</HostList></IPHostGroup></Set>"
        ).format(_xml_escape(self.group), host_xml)
        text = self._call(inner)
        if not self._status_ok(text, "IPHostGroup"):
            raise SophosError("Falha ao atualizar o grupo de bloqueio: {}".format(text[:400]))
        return text

    def block_ip(self, ip):
        """Bane um IP: cria o host e o adiciona ao grupo de bloqueio.

        Retorna dict com o resultado. Idempotente: se o IP ja estava banido,
        retorna already_blocked=True sem erro.
        """
        ip = str(ip).strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise SophosError("IP invalido: {}".format(ip))

        name = "SOC_Ban_{}".format(ip)

        hosts, grupo_ok = self._group_hosts()
        if not grupo_ok:
            existentes = self.group_names()
            if existentes:
                detalhe = "Grupos encontrados: {}. Ajuste SOPHOS_BLOCK_GROUP no .env.".format(
                    ", ".join(existentes[:15]))
            else:
                detalhe = ("Nenhum IP Host Group retornado pela API. "
                           "Resposta: {}").format(getattr(self, "_last_raw", "")[:300])
            raise SophosError(
                "Grupo de bloqueio '{}' nao encontrado. {}".format(self.group, detalhe))
        if name in hosts:
            return {"ip": ip, "already_blocked": True, "group": self.group}

        self._add_iphost(name, ip)
        self._set_group(hosts + [name])
        log.info("IP %s banido no Sophos (grupo %s).", ip, self.group)
        return {"ip": ip, "already_blocked": False, "group": self.group}


def _xml_escape(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace("\"", "&quot;"))
