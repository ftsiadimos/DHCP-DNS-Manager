"""Flask application routes."""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, g
import os
import re
from config import Config
from app.kea_client import KeaClient
from app.dns_client import DNSClient
from app.settings import (load_settings, save_settings, init_db,
                           create_user, verify_user,
                           list_zones, add_zone, delete_zone)

app = Flask(__name__)
app.config.from_object(Config)

# Ensure database exists
init_db()

kea = KeaClient()
dns_client = DNSClient()


@app.context_processor
def inject_nav_defaults():
    """Make default zone names available in every template for sidebar quick links."""
    try:
        s = load_settings()
        return {
            "nav_default_zone": s.get("default_zone", ""),
            "nav_default_reverse_zone": s.get("default_reverse_zone", ""),
        }
    except Exception:
        return {"nav_default_zone": "", "nav_default_reverse_zone": ""}


@app.before_request
def require_login():
    if request.endpoint in ("login", "logout", "static", "api_stats"):
        return
    s = load_settings()
    if s.get("disable_login"):
        g.user = "admin"
        return
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))
    g.user = session.get("username")


# ── Dashboard ───────────────────────────────────────────────

def _parse_kea_status(kea_status):
    if isinstance(kea_status, list) and kea_status:
        first = kea_status[0]
        if isinstance(first, dict):
            code = first.get("result")
            text = first.get("text") or first.get("error")
            if code == 0:
                return "UP", text or "Kea is available", "success"
            return "ERROR", text or f"Kea returned code {code}", "danger"
    if isinstance(kea_status, dict):
        code = kea_status.get("result")
        text = kea_status.get("error") or kea_status.get("text")
        if code == 0:
            return "UP", text or "Kea is available", "success"
        return "ERROR", text or "Kea status unknown", "danger"
    return "UNKNOWN", "Failed to fetch Kea status", "warning"


def _parse_dns_status(dns_status):
    if isinstance(dns_status, dict):
        if dns_status.get("error"):
            return "ERROR", dns_status.get("error"), "danger"
        if dns_status.get("success"):
            return "UP", dns_status.get("stdout") or "BIND is running", "success"
        return "UNKNOWN", dns_status.get("stderr") or "BIND status unknown", "warning"
    return "UNKNOWN", "Failed to fetch DNS status", "warning"


@app.route("/")
def index():
    kea_status_raw = kea.get_status()
    dns_status_raw = dns_client.server_status()
    kea_state, kea_text, kea_class = _parse_kea_status(kea_status_raw)
    dns_state, dns_text, dns_class = _parse_dns_status(dns_status_raw)

    try:
        subnet_count = len(kea.list_subnets())
    except Exception:
        subnet_count = "–"

    try:
        leases_raw = kea.list_leases()
        if isinstance(leases_raw, list) and leases_raw and leases_raw[0].get("result") == 0:
            lease_count = len(leases_raw[0].get("arguments", {}).get("leases", []))
        else:
            lease_count = "–"
    except Exception:
        lease_count = "–"

    return render_template("index.html",
                           kea_status=kea_status_raw,
                           dns_status=dns_status_raw,
                           kea_state=kea_state,
                           kea_text=kea_text,
                           kea_class=kea_class,
                           dns_state=dns_state,
                           dns_text=dns_text,
                           dns_class=dns_class,
                           subnet_count=subnet_count,
                           lease_count=lease_count)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = "admin"
        password = request.form.get("password", "")
        user = verify_user(username, password)
        if user:
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            if request.form.get("remember_me"):
                session.permanent = True
            flash("Logged in successfully.", "success")
            return redirect(url_for("index"))
        flash("Invalid password for admin.", "danger")
    return render_template("login.html", hide_sidebar=True)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))


# ═══════════════════════════════════════════════════════════
#  DHCP Routes
# ═══════════════════════════════════════════════════════════

@app.route("/dhcp/subnets")
def dhcp_subnets():
    subnets = kea.list_subnets()
    return render_template("dhcp/subnets.html", subnets=subnets)


@app.route("/dhcp/subnets/add", methods=["GET", "POST"])
def dhcp_subnet_add():
    if request.method == "POST":
        subnet = request.form["subnet"]
        subnet_id = int(request.form["subnet_id"])
        pool_start = request.form.get("pool_start", "")
        pool_end = request.form.get("pool_end", "")
        routers = request.form.get("routers", "")
        dns_servers = request.form.get("dns_servers", "")

        pools = []
        if pool_start and pool_end:
            pools = [{"pool": f"{pool_start}-{pool_end}"}]

        options = []
        if routers:
            options.append({"name": "routers", "data": routers})
        if dns_servers:
            options.append({"name": "domain-name-servers", "data": dns_servers})

        result = kea.add_subnet(subnet, subnet_id, pools=pools, options=options)
        flash(f"Subnet add: {result}", "info")
        return redirect(url_for("dhcp_subnets"))
    return render_template("dhcp/subnet_form.html", action="Add", subnet=None)


@app.route("/dhcp/subnets/<int:subnet_id>/edit", methods=["GET", "POST"])
def dhcp_subnet_edit(subnet_id):
    if request.method == "POST":
        subnet = request.form["subnet"]
        pool_start = request.form.get("pool_start", "")
        pool_end = request.form.get("pool_end", "")
        routers = request.form.get("routers", "")
        dns_servers = request.form.get("dns_servers", "")

        pools = []
        if pool_start and pool_end:
            pools = [{"pool": f"{pool_start}-{pool_end}"}]

        options = []
        if routers:
            options.append({"name": "routers", "data": routers})
        if dns_servers:
            options.append({"name": "domain-name-servers", "data": dns_servers})

        result = kea.update_subnet(subnet, subnet_id, pools=pools,
                                   options=options)
        flash(f"Subnet update: {result}", "info")
        return redirect(url_for("dhcp_subnets"))

    subnets = kea.list_subnets()
    subnet = next((s for s in subnets if s.get("id") == subnet_id), None)
    return render_template("dhcp/subnet_form.html", action="Edit",
                           subnet=subnet)


@app.route("/dhcp/subnets/<int:subnet_id>/delete", methods=["POST"])
def dhcp_subnet_delete(subnet_id):
    result = kea.delete_subnet(subnet_id)
    flash(f"Subnet delete: {result}", "info")
    return redirect(url_for("dhcp_subnets"))


# ── Reservations ────────────────────────────────────────────

@app.route("/dhcp/reservations/<int:subnet_id>")
def dhcp_reservations(subnet_id):
    result = kea.list_reservations(subnet_id)
    reservations = []
    try:
        if result[0]["result"] == 0:
            reservations = result[0].get("arguments", {}).get("hosts", [])
    except (IndexError, KeyError, TypeError):
        pass
    return render_template("dhcp/reservations.html", reservations=reservations,
                           subnet_id=subnet_id)


@app.route("/dhcp/reservations/<int:subnet_id>/add", methods=["GET", "POST"])
def dhcp_reservation_add(subnet_id):
    if request.method == "POST":
        hw_address = request.form["hw_address"]
        ip_address = request.form["ip_address"]
        hostname = request.form.get("hostname", "")
        result = kea.add_reservation(subnet_id, hw_address, ip_address,
                                     hostname or None)
        flash(f"Reservation add: {result}", "info")
        return redirect(url_for("dhcp_reservations", subnet_id=subnet_id))
    return render_template("dhcp/reservation_form.html", subnet_id=subnet_id)


@app.route("/dhcp/reservations/<int:subnet_id>/delete", methods=["POST"])
def dhcp_reservation_delete(subnet_id):
    ip_address = request.form["ip_address"]
    result = kea.delete_reservation(subnet_id, ip_address)
    flash(f"Reservation delete: {result}", "info")
    return redirect(url_for("dhcp_reservations", subnet_id=subnet_id))


# ── Leases ──────────────────────────────────────────────────

@app.route("/dhcp/leases")
def dhcp_leases():
    subnet_id = request.args.get("subnet_id", type=int)
    result = kea.list_leases(subnet_id)
    leases = []
    error = None
    try:
        entry = result[0]
        if entry["result"] == 0:
            leases = entry.get("arguments", {}).get("leases", [])
        else:
            error = entry.get("text") or f"Kea returned result code {entry['result']}"
    except (IndexError, KeyError, TypeError) as e:
        error = f"Unexpected response from Kea: {e} — raw: {result}"
    return render_template("dhcp/leases.html", leases=leases,
                           subnet_id=subnet_id, error=error)


@app.route("/dhcp/leases/delete", methods=["POST"])
def dhcp_lease_delete():
    ip_address = request.form["ip_address"]
    result = kea.delete_lease(ip_address)
    flash(f"Lease delete: {result}", "info")
    return redirect(url_for("dhcp_leases"))


# ═══════════════════════════════════════════════════════════
#  DNS Routes
# ═══════════════════════════════════════════════════════════

@app.route("/dns/zones", methods=["GET", "POST"])
def dns_zones():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            name = request.form.get("name", "").strip()
            zone_type = request.form.get("zone_type", "forward")
            description = request.form.get("description", "").strip()
            _, err = add_zone(name, zone_type, description)
            if err:
                flash(err, "danger")
            else:
                flash(f"Zone '{name}' added.", "success")
        elif action == "delete":
            zone_id = request.form.get("zone_id", type=int)
            err = delete_zone(zone_id)
            if err:
                flash(err, "danger")
            else:
                flash("Zone deleted.", "success")
        return redirect(url_for("dns_zones"))

    status = dns_client.server_status()
    zones = list_zones()
    return render_template("dns/zones.html", status=status, zones=zones,
                           default_zone=Config.DEFAULT_ZONE,
                           default_reverse=Config.DEFAULT_REVERSE_ZONE)


@app.route("/dns/records")
def dns_records():
    zone = request.args.get("zone", Config.DEFAULT_ZONE)
    records = dns_client.query_records(zone)
    if isinstance(records, dict) and "error" in records:
        flash(f"DNS query failed: {records['error']}", "danger")
        records = []
    return render_template("dns/records.html", records=records, zone=zone)


@app.route("/dns/records/add", methods=["GET", "POST"])
def dns_record_add():
    zone = request.args.get("zone", Config.DEFAULT_ZONE)
    if request.method == "POST":
        zone = request.form["zone"]
        name = request.form["name"]
        rtype = request.form["rtype"]
        data = request.form["data"]
        ttl = request.form.get("ttl", type=int) or Config.DEFAULT_TTL
        result = dns_client.add_record(zone, name, rtype, data, ttl)
        flash(f"DNS record add: {result}", "info")
        return redirect(url_for("dns_records", zone=zone))
    return render_template("dns/record_form.html", zone=zone, action="Add",
                           record=None,
                           supported_types=DNSClient.SUPPORTED_TYPES)


@app.route("/dns/records/edit", methods=["GET", "POST"])
def dns_record_edit():
    zone = request.args.get("zone", Config.DEFAULT_ZONE)
    if request.method == "POST":
        zone = request.form["zone"]
        name = request.form["name"]
        rtype = request.form["rtype"]
        old_data = request.form["old_data"]
        new_data = request.form["new_data"]
        ttl = request.form.get("ttl", type=int) or Config.DEFAULT_TTL
        result = dns_client.update_record(zone, name, rtype, old_data,
                                          new_data, ttl)
        flash(f"DNS record update: {result}", "info")
        return redirect(url_for("dns_records", zone=zone))
    record = {
        "name": request.args.get("name", ""),
        "type": request.args.get("rtype", "A"),
        "data": request.args.get("data", ""),
        "ttl": request.args.get("ttl", Config.DEFAULT_TTL),
    }
    return render_template("dns/record_form.html", zone=zone, action="Edit",
                           record=record,
                           supported_types=DNSClient.SUPPORTED_TYPES)


@app.route("/dns/records/delete", methods=["POST"])
def dns_record_delete():
    zone = request.form["zone"]
    name = request.form["name"]
    rtype = request.form.get("rtype")
    data = request.form.get("data")
    q = request.form.get("_q", "")
    ftype = request.form.get("_type", "")
    result = dns_client.delete_record(zone, name, rtype, data)
    flash(f"DNS record delete: {result}", "info")
    return redirect(url_for("dns_records", zone=zone, q=q, type=ftype))


@app.route("/dns/rndc", methods=["GET", "POST"])
def dns_rndc():
    output = None
    if request.method == "POST":
        cmd = request.form["command"]
        # Whitelist safe rndc commands
        allowed = {"status", "reload", "refresh", "flush", "dumpdb",
                   "zonestatus", "reconfig", "freeze", "thaw", "sync",
                   "stats"}
        base_cmd = cmd.split()[0] if cmd else ""
        if base_cmd not in allowed:
            flash(f"Command '{base_cmd}' not allowed. Allowed: {allowed}",
                  "danger")
        else:
            output = dns_client.rndc(cmd)
    return render_template("dns/rndc.html", output=output)


# ═══════════════════════════════════════════════════════════
#  Settings
# ═══════════════════════════════════════════════════════════

@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        new_settings = {
            "kea_api_url": request.form.get("kea_api_url", "").strip(),
            "kea_user": request.form.get("kea_user", "").strip(),
            "kea_password": request.form.get("kea_password", "").strip(),
            "dns_server": request.form.get("dns_server", "").strip(),
            "dns_port": int(request.form.get("dns_port") or 53),
            "stats_port": int(request.form.get("stats_port") or 8053),
            "rndc_host": request.form.get("rndc_host", "").strip(),
            "rndc_port": int(request.form.get("rndc_port") or 953),
            "rndc_bin": request.form.get("rndc_bin", "").strip(),
            "rndc_key": request.form.get("rndc_key", "").strip(),
            "tsig_key_name": request.form.get("tsig_key_name", "").strip(),
            "tsig_key_secret": request.form.get("tsig_key_secret", "").strip(),
            "tsig_key_algorithm": request.form.get("tsig_key_algorithm", "").strip(),
            "default_zone": request.form.get("default_zone", "").strip(),
            "default_reverse_zone": request.form.get("default_reverse_zone", "").strip(),
            "default_ttl": int(request.form.get("default_ttl") or 3600),
            "disable_login": "true" if request.form.get("disable_login") else "false",
        }
        # Auto-parse removed — rndc_key is now the raw secret only
        save_settings(new_settings)
        flash("Settings saved successfully.", "success")
        return redirect(url_for("settings"))
    current = load_settings()
    return render_template("settings.html", settings=current)


# ═══════════════════════════════════════════════════════════
#  User / Account
# ═══════════════════════════════════════════════════════════

@app.route("/about")
def about():
    try:
        with open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "VERSION")) as _f:
            version = _f.read().strip()
    except Exception:
        version = "unknown"
    return render_template("about.html", version=version)


@app.route("/account", methods=["GET", "POST"])
def account():
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")
        if not new_pw:
            flash("New password cannot be empty.", "danger")
        elif new_pw != confirm_pw:
            flash("New passwords do not match.", "danger")
        else:
            from app.settings import verify_user
            from app.db import SessionLocal
            from app.models import User
            from werkzeug.security import generate_password_hash
            user = verify_user("admin", current_pw)
            if not user:
                flash("Current password is incorrect.", "danger")
            else:
                with SessionLocal() as db_session:
                    u = db_session.query(User).filter_by(username="admin").first()
                    u.password_hash = generate_password_hash(new_pw)
                    db_session.commit()
                flash("Password updated successfully.", "success")
                return redirect(url_for("account"))
    return render_template("account.html")


# ═══════════════════════════════════════════════════════════
#  JSON API (for scripting / automation)
# ═══════════════════════════════════════════════════════════

@app.route("/api/dhcp/subnets")
def api_dhcp_subnets():
    return jsonify(kea.list_subnets())


@app.route("/api/dhcp/leases")
def api_dhcp_leases():
    sid = request.args.get("subnet_id", type=int)
    return jsonify(kea.list_leases(sid))


@app.route("/api/dhcp/reservations/<int:subnet_id>")
def api_dhcp_reservations(subnet_id):
    return jsonify(kea.list_reservations(subnet_id))


@app.route("/api/dns/records")
def api_dns_records():
    zone = request.args.get("zone", Config.DEFAULT_ZONE)
    return jsonify(dns_client.query_records(zone))


@app.route("/api/dns/record", methods=["POST"])
def api_dns_record_add():
    data = request.get_json()
    result = dns_client.add_record(
        data["zone"], data["name"], data["rtype"], data["data"],
        data.get("ttl"))
    return jsonify(result)


@app.route("/api/dns/record", methods=["DELETE"])
def api_dns_record_del():
    data = request.get_json()
    result = dns_client.delete_record(
        data["zone"], data["name"], data.get("rtype"), data.get("data"))
    return jsonify(result)


@app.route("/api/stats")
def api_stats():
    """Return DHCP lease count and DNS zone/record stats."""
    lease_count = 0
    lease_error = None
    try:
        result = kea.list_leases()
        entry = result[0]
        if entry["result"] == 0:
            lease_count = len(entry.get("arguments", {}).get("leases", []))
        else:
            lease_error = entry.get("text")
    except Exception as e:
        lease_error = str(e)

    dns_stats = dns_client.get_stats()

    return jsonify({
        "dhcp": {
            "total_leases": lease_count,
            "error": lease_error,
        },
        "dns": dns_stats,
    })
