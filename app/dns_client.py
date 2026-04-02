"""BIND/named DNS management via dnspython and rndc."""

import subprocess
import tempfile
import os
import shutil
import dns.query
import dns.tsigkeyring
import dns.update
import dns.resolver
import dns.reversename
import dns.name
from config import Config


class DNSClient:
    """Manage DNS records via dynamic updates (nsupdate) and rndc."""

    SUPPORTED_TYPES = ("A", "AAAA", "CNAME", "MX", "TXT", "PTR", "NS", "SRV")

    ALGO_MAP = {
        "hmac-md5": dns.tsig.HMAC_MD5,
        "hmac-sha1": dns.tsig.HMAC_SHA1,
        "hmac-sha256": dns.tsig.HMAC_SHA256,
        "hmac-sha384": dns.tsig.HMAC_SHA384,
        "hmac-sha512": dns.tsig.HMAC_SHA512,
    }

    def __init__(self):
        pass

    @property
    def server(self):
        return Config.DNS_SERVER

    @property
    def port(self):
        return int(Config.DNS_PORT)

    @property
    def tsig_keyring(self):
        if Config.TSIG_KEY_SECRET:
            return dns.tsigkeyring.from_text({
                Config.TSIG_KEY_NAME: Config.TSIG_KEY_SECRET,
            })
        return None

    @property
    def tsig_algorithm(self):
        return self.ALGO_MAP.get(
            Config.TSIG_KEY_ALGORITHM.lower(), dns.tsig.HMAC_SHA256
        )

    # ── Queries ─────────────────────────────────────────────

    def _resolve_server(self):
        """Return the DNS server as an IP address (resolves hostname if needed)."""
        import socket
        host = self.server
        try:
            dns.inet.af_for_address(host)
            return host  # already an IP
        except ValueError:
            return socket.gethostbyname(host)

    def query_records(self, zone, rtype="A"):
        """Query all records in a zone via AXFR, trying TSIG first then plain."""
        records = []
        last_error = None
        attempts = [(self.tsig_keyring, self.tsig_algorithm)]
        if self.tsig_keyring is not None:
            attempts.append((None, None))  # fallback: plain AXFR
        for keyring, keyalgorithm in attempts:
            try:
                xfr_kwargs = {"port": self.port}
                if keyring is not None:
                    xfr_kwargs["keyring"] = keyring
                    xfr_kwargs["keyalgorithm"] = keyalgorithm
                z = dns.zone.from_xfr(
                    dns.query.xfr(self._resolve_server(), zone, **xfr_kwargs)
                )
                for name, node in z.nodes.items():
                    for rdataset in node.rdatasets:
                        for rdata in rdataset:
                            records.append({
                                "name": str(name),
                                "ttl": rdataset.ttl,
                                "type": dns.rdatatype.to_text(rdataset.rdtype),
                                "data": str(rdata),
                            })
                return records  # success
            except Exception as e:
                last_error = str(e)
        return {"error": (
            f"{last_error}. "
            "Ensure AXFR is permitted from this host in named.conf: "
            "allow-transfer { this_server_ip; };"
        )}
        return records

    def resolve_record(self, name, rtype="A"):
        """Resolve a single record."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self._resolve_server()]
            resolver.port = self.port
            answers = resolver.resolve(name, rtype)
            return [{"name": name, "type": rtype, "ttl": answers.rrset.ttl,
                      "data": str(r)} for r in answers]
        except Exception as e:
            return {"error": str(e)}

    # ── Dynamic Updates ─────────────────────────────────────

    def _make_update(self, zone):
        update = dns.update.Update(
            zone,
            keyring=self.tsig_keyring,
            keyalgorithm=self.tsig_algorithm,
        )
        return update

    def add_record(self, zone, name, rtype, data, ttl=None):
        """Add a DNS record."""
        ttl = ttl or Config.DEFAULT_TTL
        if rtype.upper() not in self.SUPPORTED_TYPES:
            return {"error": f"Unsupported record type: {rtype}"}
        try:
            update = self._make_update(zone)
            update.add(name, ttl, rtype.upper(), data)
            resp = dns.query.tcp(update, self._resolve_server(), port=self.port, timeout=10)
            rcode = resp.rcode()
            return {"success": rcode == 0,
                    "rcode": dns.rcode.to_text(rcode)}
        except Exception as e:
            return {"error": str(e)}

    def delete_record(self, zone, name, rtype=None, data=None):
        """Delete a DNS record. If rtype/data omitted, deletes all records for name."""
        try:
            update = self._make_update(zone)
            if rtype and data:
                update.delete(name, rtype.upper(), data)
            elif rtype:
                update.delete(name, rtype.upper())
            else:
                update.delete(name)
            resp = dns.query.tcp(update, self._resolve_server(), port=self.port, timeout=10)
            rcode = resp.rcode()
            return {"success": rcode == 0,
                    "rcode": dns.rcode.to_text(rcode)}
        except Exception as e:
            return {"error": str(e)}

    def update_record(self, zone, name, rtype, old_data, new_data, ttl=None):
        """Replace a record (delete old + add new)."""
        ttl = ttl or Config.DEFAULT_TTL
        try:
            update = self._make_update(zone)
            update.delete(name, rtype.upper(), old_data)
            update.add(name, ttl, rtype.upper(), new_data)
            resp = dns.query.tcp(update, self._resolve_server(), port=self.port, timeout=10)
            rcode = resp.rcode()
            return {"success": rcode == 0,
                    "rcode": dns.rcode.to_text(rcode)}
        except Exception as e:
            return {"error": str(e)}

    # ── PTR / Reverse ───────────────────────────────────────

    def add_ptr(self, ip_address, hostname, zone=None, ttl=None):
        """Add a PTR record for an IP."""
        ttl = ttl or Config.DEFAULT_TTL
        zone = zone or Config.DEFAULT_REVERSE_ZONE
        rev = dns.reversename.from_address(ip_address)
        ptr_name = str(rev).replace("." + zone + ".", "")
        return self.add_record(zone, ptr_name, "PTR",
                               hostname if hostname.endswith(".") else hostname + ".",
                               ttl)

    def delete_ptr(self, ip_address, zone=None):
        """Delete a PTR record for an IP."""
        zone = zone or Config.DEFAULT_REVERSE_ZONE
        rev = dns.reversename.from_address(ip_address)
        ptr_name = str(rev).replace("." + zone + ".", "")
        return self.delete_record(zone, ptr_name, "PTR")

    # ── rndc ────────────────────────────────────────────────

    def _find_rndc(self):
        """Locate the rndc binary from settings, PATH, or common paths."""
        configured = Config.RNDC_BIN.strip() if Config.RNDC_BIN else ""
        if configured:
            return configured if os.path.isfile(configured) else None
        found = shutil.which("rndc")
        if found:
            return found
        for path in ("/usr/sbin/rndc", "/sbin/rndc", "/usr/bin/rndc",
                     "/usr/local/sbin/rndc", "/usr/local/bin/rndc"):
            if os.path.isfile(path):
                return path
        return None

    def rndc(self, command):
        """Execute an rndc command on the host."""
        rndc_bin = self._find_rndc()
        if not rndc_bin:
            return {
                "success": False,
                "error": (
                    "rndc binary not found. Install it with: "
                    "'dnf install bind-utils' (RHEL/CentOS) or "
                    "'apt install bind9-utils' (Debian/Ubuntu), "
                    "or set the path in Settings → RNDC Binary Path."
                ),
            }
        cmd = [rndc_bin, "-s", self.server, "-p", str(Config.RNDC_PORT)]
        secret = Config.RNDC_KEY
        tmp_key = None
        try:
            if secret and secret.strip():
                key_file_content = (
                    f'key "{Config.TSIG_KEY_NAME}" {{\n'
                    f'    algorithm {Config.TSIG_KEY_ALGORITHM};\n'
                    f'    secret "{secret.strip()}";\n'
                    f'}};\n'
                )
                tmp = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".key", delete=False
                )
                tmp.write(key_file_content)
                tmp.close()
                tmp_key = tmp.name
                cmd += ["-k", tmp_key]
            cmd += command.split()
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=10)
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
            }
        except Exception as e:
            return {"error": str(e)}
        finally:
            if tmp_key and os.path.exists(tmp_key):
                os.unlink(tmp_key)

    def reload_zone(self, zone):
        return self.rndc(f"reload {zone}")

    def freeze_zone(self, zone):
        return self.rndc(f"freeze {zone}")

    def thaw_zone(self, zone):
        return self.rndc(f"thaw {zone}")

    def server_status(self):
        return self.rndc("status")

    def list_zones(self):
        """Get zone list from rndc zonestatus or status."""
        return self.rndc("zonestatus")

    # Built-in BIND zones that should be excluded from user-visible counts
    _BUILTIN_ZONES = {
        ".", "localhost", "local",
        "0.in-addr.arpa", "127.in-addr.arpa", "255.in-addr.arpa",
        "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa",
    }

    @staticmethod
    def _strip_zone_class(name: str) -> str:
        """BIND stats report zones as 'example.com/IN' — strip the class suffix."""
        return name.split("/")[0].rstrip(".")

    def _is_builtin_zone(self, name: str) -> bool:
        return self._strip_zone_class(name).lower() in self._BUILTIN_ZONES

    def _count_records_axfr(self, zone_names: list) -> int:
        """AXFR each zone and sum type-A record counts. Returns int or '–' on total failure."""
        total = 0
        any_success = False
        for zone in zone_names:
            try:
                records = self.query_records(zone)
                if isinstance(records, list):
                    total += sum(1 for r in records if r.get("type") == "A")
                    any_success = True
            except Exception:
                pass
        return total if any_success else "–"

    def get_stats(self):
        """Fetch BIND statistics.

        Tries (in order):
          1. BIND HTTP stats-channels JSON  (port stats_port, BIND 9.10+)
          2. BIND HTTP stats-channels XML   (same port)
          3. rndc status output             (parses "number of zones" line)

        NOTE: BIND's statistics-channels do NOT report per-zone record counts.
        Record counts are obtained via AXFR for each user zone.

        Returns a dict with keys: zone_count, total_records, zones, error.
        """
        import requests as _requests
        import xml.etree.ElementTree as ET
        import re

        stats_port = int(getattr(Config, "STATS_PORT", 8053))
        base_url = f"http://{self.server}:{stats_port}"

        # 1 — JSON endpoint (BIND 9.10+)
        try:
            r = _requests.get(f"{base_url}/json/v1", timeout=3)
            r.raise_for_status()
            data = r.json()
            # Zones live under views._default.zones or top-level zones
            raw_zones = data.get("views", {}).get("_default", {}).get("zones", [])
            if not raw_zones:
                raw_zones = data.get("zones", [])
            user_zones = [
                self._strip_zone_class(z["name"])
                for z in raw_zones
                if z.get("name") and not self._is_builtin_zone(z["name"])
            ]
            total_records = self._count_records_axfr(user_zones)
            return {"zone_count": len(user_zones), "total_records": total_records,
                    "zones": user_zones}
        except Exception:
            pass

        # 2 — XML endpoint
        try:
            r = _requests.get(f"{base_url}/", timeout=3)
            r.raise_for_status()
            root = ET.fromstring(r.text)
            ns = {"b": root.tag.split("}")[0].lstrip("{")} if "}" in root.tag else {}
            zones_el = root.findall(".//b:zones/b:zone", ns) if ns else root.findall(".//zones/zone")
            user_zones = []
            for z in zones_el:
                name_el = z.find("b:name" if ns else "name", ns)
                if name_el is not None and name_el.text and not self._is_builtin_zone(name_el.text):
                    user_zones.append(self._strip_zone_class(name_el.text))
            total_records = self._count_records_axfr(user_zones)
            return {"zone_count": len(user_zones), "total_records": total_records,
                    "zones": user_zones}
        except Exception:
            pass

        # 3 — rndc status fallback: parse "number of zones: N"
        try:
            status = self.rndc("status")
            stdout = status.get("stdout", "")
            m = re.search(r"number of zones:\s*(\d+)", stdout, re.IGNORECASE)
            zone_count = int(m.group(1)) if m else "–"
            return {"zone_count": zone_count, "total_records": "–", "zones": [],
                    "note": "Zone count from rndc status (stats-channels not configured)"}
        except Exception:
            pass

        return {"error": f"Stats channel unavailable on port {stats_port}. "
                         "Enable with: statistics-channels { inet * port 8053 allow { any; }; }; in named.conf",
                "zone_count": "–", "total_records": "–", "zones": []}
