"""Kea DHCP Control Agent client."""

import requests
from config import Config


class KeaClient:
    """Client for the Kea Control Agent REST API."""

    def __init__(self):
        pass

    @property
    def api_url(self):
        return Config.KEA_API_URL

    @property
    def _auth(self):
        user = Config.KEA_USER
        password = Config.KEA_PASSWORD
        return (user, password) if user else None

    def _send(self, command, service=None, arguments=None):
        """Send a command to Kea Control Agent."""
        payload = {"command": command}
        if service:
            payload["service"] = service if isinstance(service, list) else [service]
        if arguments:
            payload["arguments"] = arguments
        try:
            resp = requests.post(self.api_url, json=payload, timeout=10,
                                 auth=self._auth)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            return [{"result": 1, "text": str(e)}]

    # ── Status ──────────────────────────────────────────────

    def get_version(self):
        return self._send("version-get", service="dhcp4")

    def get_status(self):
        return self._send("status-get", service="dhcp4")

    def get_config(self):
        return self._send("config-get", service="dhcp4")

    # ── Subnets ─────────────────────────────────────────────

    def list_subnets(self):
        result = self._send("config-get", service="dhcp4")
        try:
            cfg = result[0]["arguments"]["Dhcp4"]
            return cfg.get("subnet4", [])
        except (KeyError, IndexError, TypeError):
            return []

    def get_subnet(self, subnet_id):
        result = self._send("subnet4-get", service="dhcp4",
                            arguments={"id": subnet_id})
        return result

    def add_subnet(self, subnet, subnet_id, pools=None, options=None,
                   reservations=None):
        args = {
            "subnet4": [{
                "id": subnet_id,
                "subnet": subnet,
                "pools": pools or [],
                "option-data": options or [],
                "reservations": reservations or [],
            }]
        }
        return self._send("subnet4-add", service="dhcp4", arguments=args)

    def update_subnet(self, subnet, subnet_id, pools=None, options=None,
                      reservations=None):
        args = {
            "subnet4": [{
                "id": subnet_id,
                "subnet": subnet,
                "pools": pools or [],
                "option-data": options or [],
                "reservations": reservations or [],
            }]
        }
        return self._send("subnet4-update", service="dhcp4", arguments=args)

    def delete_subnet(self, subnet_id):
        return self._send("subnet4-del", service="dhcp4",
                          arguments={"id": subnet_id})

    # ── Reservations ────────────────────────────────────────

    def list_reservations(self, subnet_id):
        # Try reservation-get-all (requires host backend / lease_cmds hook)
        result = self._send("reservation-get-all", service="dhcp4",
                            arguments={"subnet-id": subnet_id})
        try:
            if result[0]["result"] == 0:
                hosts = result[0].get("arguments", {}).get("hosts", [])
                if hosts:
                    return result
        except (IndexError, KeyError, TypeError):
            pass
        # Fall back: read inline reservations from the running config
        try:
            cfg_result = self._send("config-get", service="dhcp4")
            subnets = cfg_result[0]["arguments"]["Dhcp4"].get("subnet4", [])
            for subnet in subnets:
                if subnet.get("id") == subnet_id:
                    hosts = subnet.get("reservations", [])
                    return [{"result": 0, "arguments": {"hosts": hosts}}]
        except (IndexError, KeyError, TypeError):
            pass
        return [{"result": 0, "arguments": {"hosts": []}}]

    def add_reservation(self, subnet_id, hw_address, ip_address,
                        hostname=None):
        args = {
            "reservation": {
                "subnet-id": subnet_id,
                "hw-address": hw_address,
                "ip-address": ip_address,
            }
        }
        if hostname:
            args["reservation"]["hostname"] = hostname
        return self._send("reservation-add", service="dhcp4", arguments=args)

    def delete_reservation(self, subnet_id, ip_address):
        return self._send("reservation-del", service="dhcp4",
                          arguments={
                              "subnet-id": subnet_id,
                              "ip-address": ip_address,
                          })

    # ── Leases ──────────────────────────────────────────────

    def list_leases(self, subnet_id=None):
        if subnet_id is not None:
            return self._send("lease4-get-all", service="dhcp4",
                              arguments={"subnets": [subnet_id]})
        return self._send("lease4-get-all", service="dhcp4")

    def get_lease(self, ip_address):
        return self._send("lease4-get", service="dhcp4",
                          arguments={"ip-address": ip_address})

    def delete_lease(self, ip_address):
        return self._send("lease4-del", service="dhcp4",
                          arguments={"ip-address": ip_address})

    def wipe_leases(self, subnet_id):
        return self._send("lease4-wipe", service="dhcp4",
                          arguments={"subnet-id": subnet_id})
