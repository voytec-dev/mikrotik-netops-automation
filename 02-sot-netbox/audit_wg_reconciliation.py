import argparse
import csv
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.request

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def env_bool(name, default=False):
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


# =====================================================================
# 1. KONFIGURACJA POŁĄCZENIA (READ-ONLY)
# =====================================================================
NETBOX_URL = os.getenv("NETBOX_URL", "http://netbox.local:8000")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN", "")
NETBOX_VERIFY_SSL = env_bool("NETBOX_VERIFY_SSL", True)

MGMT_VPN_ROLE_NAME = os.getenv("MGMT_VPN_ROLE_NAME", "Wireguard Management")
FALLBACK_MGMT_SUPERNET = ipaddress.ip_network(
    os.getenv("FALLBACK_MGMT_SUPERNET", "10.0.0.0/22")
)
OXIDIZED_TAG_NAME = os.getenv("OXIDIZED_TAG_NAME", "oxidized")
OXIDIZED_URL = os.getenv("OXIDIZED_URL", "").strip()


# =====================================================================
# 2. PARSER ZRZUTU ROUTEROS (/interface/wireguard/peers/print terse)
# =====================================================================
NEW_PEER_RE = re.compile(
    r"^\s*(\d+)\s+(?:([A-Z]{1,4})\s+)?(?=(?:comment|interface)=)"
)
KV_PAIR_RE = re.compile(r'([a-zA-Z0-9-]+)=("(?:\\.|[^"])*"|\S*)')
SN_COMMENT_RE = re.compile(r"^[A-Z0-9]{11,12}$")
SN_ENDPOINT_RE = re.compile(r"^([a-z0-9]+)\.sn\.mynetname\.net$", re.I)
ROS_DURATION_RE = re.compile(
    r"^(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?(?:(\d+)ms)?$"
)


def parse_ros_duration_seconds(duration_str):
    """Konwertuje czas RouterOS (np. '4w1d14h54m10s', '37s') na sekundy."""
    if not duration_str:
        return None
    val = duration_str.strip()
    if not val:
        return None
    m = ROS_DURATION_RE.fullmatch(val)
    if not m:
        return None
    weeks, days, hours, minutes, seconds, millis = (
        int(x) if x is not None else 0 for x in m.groups()
    )
    total = weeks * 604800 + days * 86400 + hours * 3600 + minutes * 60 + seconds
    if total == 0 and millis > 0:
        return 0
    return total


def format_duration_human(seconds):
    """Formatuje liczbę sekund do zwięzłej postaci czytelnej dla człowieka."""
    if seconds is None:
        return "brak"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60}s"
    if seconds < 86400:
        h = seconds // 3600
        m = (seconds % 3600) // 60
        return f"{h}h{m}m"
    d = seconds // 86400
    h = (seconds % 86400) // 3600
    return f"{d}d{h}h"


def merge_wrapped_terse_lines(raw_text):
    """
    Skleja linie złamane przez terminal podczas 'print terse' (bez 'without-paging').
    Zachowuje spacje na początku kontynuacji, aby bezbłędnie odtworzyć rozcięte klucze i adresy IP.
    """
    entries = []
    current = ""
    for raw_line in raw_text.splitlines():
        line_no_eol = raw_line.rstrip("\r\n")
        stripped = line_no_eol.strip()
        if not stripped:
            continue
        if stripped.startswith("[") and ">" in stripped:
            continue
        if stripped.startswith("-- [Q quit"):
            continue

        if NEW_PEER_RE.match(line_no_eol):
            if current:
                entries.append(current)
            current = line_no_eol
        else:
            if current:
                current += line_no_eol
    if current:
        entries.append(current)
    return entries


def extract_mgmt_ip(allowed_address_str, mgmt_networks):
    """Wybiera adres IP z globalnej sieci zarządzania spośród wpisów allowed-address."""
    fallback_first_ip = None
    for cidr in str(allowed_address_str).split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            ip_iface = ipaddress.ip_interface(cidr)
        except ValueError:
            continue
        if fallback_first_ip is None and ip_iface.network.prefixlen == 32:
            fallback_first_ip = str(ip_iface.ip)
        for net in mgmt_networks:
            if ip_iface.ip in net:
                return str(ip_iface.ip)
    return fallback_first_ip


def parse_wg_peers_terse(raw_text, mgmt_networks):
    """Parsuje wyjście '/interface/wireguard/peers/print terse' do listy słowników."""
    peers = []
    for entry_line in merge_wrapped_terse_lines(raw_text):
        head_match = NEW_PEER_RE.match(entry_line)
        if not head_match:
            continue

        idx = int(head_match.group(1))
        flags = (head_match.group(2) or "").upper()
        is_disabled = "X" in flags

        rest = entry_line[head_match.end() :]
        params = {}
        for key, raw_val in KV_PAIR_RE.findall(rest):
            if raw_val.startswith('"') and raw_val.endswith('"') and len(raw_val) >= 2:
                params[key] = raw_val[1:-1]
            else:
                params[key] = raw_val

        comment = params.get("comment", "").strip()
        endpoint = params.get("endpoint-address", "").strip()
        serial = ""
        if SN_COMMENT_RE.match(comment.upper()):
            serial = comment.upper()
        else:
            ep_match = SN_ENDPOINT_RE.match(endpoint)
            if ep_match:
                serial = ep_match.group(1).upper()

        allowed_str = params.get("allowed-address", "")
        mgmt_ip = extract_mgmt_ip(allowed_str, mgmt_networks)
        handshake_raw = params.get("last-handshake", "")
        handshake_sec = parse_ros_duration_seconds(handshake_raw)

        peers.append(
            {
                "index": idx,
                "flags": flags,
                "disabled": is_disabled,
                "name": params.get("name", "").strip(),
                "interface": params.get("interface", "").strip(),
                "comment": comment,
                "serial": serial,
                "mgmt_ip": mgmt_ip or "",
                "allowed_address": allowed_str,
                "last_handshake_raw": handshake_raw,
                "last_handshake_sec": handshake_sec,
                "rx": params.get("rx", ""),
                "tx": params.get("tx", ""),
            }
        )
    return peers


# =====================================================================
# 3. POBIERANIE DANYCH Z NETBOX ORAZ OXIDIZED (READ-ONLY)
# =====================================================================
def make_slug(text):
    slug = text.lower()
    replacements = {
        "ą": "a", "ć": "c", "ę": "e", "ł": "l",
        "ń": "n", "ó": "o", "ś": "s", "ź": "z", "ż": "z",
    }
    for pl, ascii_char in replacements.items():
        slug = slug.replace(pl, ascii_char)
    return re.sub(r"[^a-z0-9]+", "-", slug).strip("-")


def init_netbox():
    if not NETBOX_TOKEN:
        print(
            "[X] Brak zmiennej NETBOX_TOKEN. Skopiuj .env.example do .env i uzupełnij dane dostępowe."
        )
        sys.exit(1)
    try:
        import pynetbox
    except ImportError:
        print("[X] Brak pakietu 'pynetbox'. Zainstaluj zależności: pip install -r requirements.txt")
        sys.exit(1)

    nb = pynetbox.api(NETBOX_URL, token=NETBOX_TOKEN)
    nb.http_session.verify = NETBOX_VERIFY_SSL
    return nb


def fetch_global_mgmt_networks(nb):
    nets = []
    try:
        role_slug = make_slug(MGMT_VPN_ROLE_NAME)
        roles = list(nb.ipam.roles.filter(slug=role_slug)) or list(
            nb.ipam.roles.filter(name=MGMT_VPN_ROLE_NAME)
        )
        if roles:
            for p in nb.ipam.prefixes.filter(role_id=roles[0].id):
                if getattr(p, "vrf", None) is None:
                    try:
                        nets.append(ipaddress.ip_network(p.prefix, strict=False))
                    except ValueError:
                        pass
    except Exception as e:
        print(f"[!] Ostrzeżenie przy pobieraniu prefiksów '{MGMT_VPN_ROLE_NAME}': {e}")

    if not nets:
        nets.append(FALLBACK_MGMT_SUPERNET)
    return nets


def fetch_netbox_inventory(nb, mgmt_networks):
    """Pobiera urządzenia z NetBoxa i indeksuje je po IP zarządzania, SN oraz nazwie."""
    all_devices = []
    by_mgmt_ip = {}
    by_serial = {}
    by_name = {}

    for dev in nb.dcim.devices.all():
        primary_ip = ""
        is_mgmt_ip = False
        if getattr(dev, "primary_ip4", None) and getattr(dev.primary_ip4, "address", None):
            try:
                ip_if = ipaddress.ip_interface(dev.primary_ip4.address)
                primary_ip = str(ip_if.ip)
                is_mgmt_ip = any(ip_if.ip in net for net in mgmt_networks)
            except ValueError:
                pass

        status_obj = getattr(dev, "status", None)
        status_val = str(getattr(status_obj, "value", status_obj or "")).lower()

        platform_obj = getattr(dev, "platform", None)
        platform_slug = str(getattr(platform_obj, "slug", "") or "").lower()

        tags = set()
        for t in getattr(dev, "tags", None) or []:
            t_slug = getattr(t, "slug", None) if not isinstance(t, dict) else t.get("slug")
            t_name = getattr(t, "name", None) if not isinstance(t, dict) else t.get("name")
            if t_slug:
                tags.add(str(t_slug).lower())
            if t_name:
                tags.add(str(t_name).lower())

        info = {
            "id": dev.id,
            "name": dev.name,
            "serial": (getattr(dev, "serial", "") or "").strip().upper(),
            "status": status_val,
            "platform_slug": platform_slug,
            "primary_ip": primary_ip,
            "is_mgmt_ip": is_mgmt_ip,
            "tags": tags,
        }
        all_devices.append(info)

        if primary_ip and is_mgmt_ip:
            by_mgmt_ip[primary_ip] = info
        if info["serial"]:
            by_serial[info["serial"]] = info
        if info["name"]:
            by_name[info["name"].upper()] = info

    return {
        "all": all_devices,
        "by_mgmt_ip": by_mgmt_ip,
        "by_serial": by_serial,
        "by_name": by_name,
    }


def fetch_oxidized_nodes(oxidized_url):
    """Pobiera opcjonalnie stan węzłów z REST API Oxidized (/nodes.json)."""
    if not oxidized_url:
        return None
    url = f"{oxidized_url.rstrip('/')}/nodes.json"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        print(f"[!] Ostrzeżenie: nie udało się pobrać {url}: {e}")
        return None

    by_ip = {}
    by_name = {}
    for node in payload:
        if not isinstance(node, dict):
            continue
        last_info = node.get("last") or {}
        entry = {
            "name": str(node.get("name", "")),
            "ip": str(node.get("ip", "")).split("/")[0],
            "model": str(node.get("model", "")),
            "status": str(node.get("status", "")),
            "last_status": str(last_info.get("status", "never")),
        }
        if entry["ip"]:
            by_ip[entry["ip"]] = entry
        if entry["name"]:
            by_name[entry["name"].upper()] = entry
    return {"by_ip": by_ip, "by_name": by_name, "count": len(payload)}


# =====================================================================
# 4. SILNIK PORÓWNAWCZY (3-WAY RECONCILIATION)
# =====================================================================
def find_netbox_match(peer, nb_inv):
    """Dopasowuje peera WG do urządzenia w NetBoxie: po IP MGMT, SN lub nazwie."""
    if peer["mgmt_ip"] and peer["mgmt_ip"] in nb_inv["by_mgmt_ip"]:
        return nb_inv["by_mgmt_ip"][peer["mgmt_ip"]], "ip"
    if peer["serial"] and peer["serial"] in nb_inv["by_serial"]:
        return nb_inv["by_serial"][peer["serial"]], "serial"
    if peer["name"] and peer["name"].upper() in nb_inv["by_name"]:
        return nb_inv["by_name"][peer["name"].upper()], "name"
    return None, None


def find_oxidized_node(nb_dev, ox_data):
    if not ox_data or not nb_dev:
        return None
    if nb_dev["primary_ip"] and nb_dev["primary_ip"] in ox_data["by_ip"]:
        return ox_data["by_ip"][nb_dev["primary_ip"]]
    return ox_data["by_name"].get(nb_dev["name"].upper())


def reconcile(peers, nb_inv, ox_data, stale_days=7):
    stale_seconds = stale_days * 86400
    matched_peer_by_nb_id = {}

    missing_in_netbox = []
    active_not_active_in_netbox = []
    stale_or_disabled = []

    for peer in peers:
        nb_dev, match_type = find_netbox_match(peer, nb_inv)
        if nb_dev:
            matched_peer_by_nb_id[nb_dev["id"]] = peer

        hs_sec = peer["last_handshake_sec"]
        is_fresh = (not peer["disabled"]) and (hs_sec is not None) and (hs_sec <= stale_seconds)

        if is_fresh:
            if not nb_dev:
                missing_in_netbox.append(
                    {
                        "bucket": "1_WG_ACTIVE_MISSING_IN_NETBOX",
                        "wg_ip": peer["mgmt_ip"],
                        "wg_name": peer["name"],
                        "serial": peer["serial"],
                        "handshake": format_duration_human(hs_sec),
                        "netbox_name": "-",
                        "netbox_status": "BRAK",
                        "oxidized_status": "-",
                        "action": "Pobierz .rsc i dodaj przez sync_mikrotik_to_netbox.py --only-new",
                    }
                )
            elif nb_dev["status"] != "active":
                active_not_active_in_netbox.append(
                    {
                        "bucket": "2_WG_ACTIVE_WRONG_NB_STATUS",
                        "wg_ip": peer["mgmt_ip"],
                        "wg_name": peer["name"],
                        "serial": peer["serial"] or nb_dev["serial"],
                        "handshake": format_duration_human(hs_sec),
                        "netbox_name": nb_dev["name"],
                        "netbox_status": nb_dev["status"],
                        "oxidized_status": "-",
                        "action": f"Zmień status w NetBox z '{nb_dev['status']}' na 'active' (match: {match_type})",
                    }
                )
        else:
            if peer["disabled"]:
                reason = "disabled=yes"
            elif hs_sec is None:
                reason = "brak handshake"
            else:
                reason = f"stary handshake ({format_duration_human(hs_sec)})"

            nb_status = nb_dev["status"] if nb_dev else "BRAK"
            if not nb_dev:
                rec = f"{reason}: zweryfikuj czy oczekuje na montaż (staged), czy do usunięcia z WG"
            elif nb_status == "active":
                rec = f"{reason}: jeśli lokalizacja zlikwidowana -> NetBox 'offline' + WG 'disabled=yes'"
            else:
                rec = f"{reason}: stan spójny z NetBox '{nb_status}' (sprawdź czy nie usunąć klucza z WG)"

            stale_or_disabled.append(
                {
                    "bucket": "3_WG_STALE_OR_DISABLED",
                    "wg_ip": peer["mgmt_ip"],
                    "wg_name": peer["name"],
                    "serial": peer["serial"] or (nb_dev["serial"] if nb_dev else ""),
                    "handshake": "disabled" if peer["disabled"] else format_duration_human(hs_sec),
                    "netbox_name": nb_dev["name"] if nb_dev else "-",
                    "netbox_status": nb_status,
                    "oxidized_status": "-",
                    "action": rec,
                }
            )

    netbox_orphans = []
    oxidized_issues = []
    ox_tag_lower = OXIDIZED_TAG_NAME.lower()

    for nb_dev in nb_inv["all"]:
        if not nb_dev["is_mgmt_ip"]:
            continue

        if nb_dev["status"] == "active" and nb_dev["id"] not in matched_peer_by_nb_id:
            netbox_orphans.append(
                {
                    "bucket": "4_NETBOX_ACTIVE_MISSING_IN_WG",
                    "wg_ip": nb_dev["primary_ip"],
                    "wg_name": "-",
                    "serial": nb_dev["serial"],
                    "handshake": "-",
                    "netbox_name": nb_dev["name"],
                    "netbox_status": nb_dev["status"],
                    "oxidized_status": "-",
                    "action": "Urządzenie aktywne w NetBox, brak na Core Routerze WG -> zmień na 'offline'",
                }
            )

        if nb_dev["status"] == "active" and nb_dev["platform_slug"] != "swos":
            ox_node = find_oxidized_node(nb_dev, ox_data)
            ox_state = ox_node["last_status"] if ox_node else ("BRAK_W_OXIDIZED" if ox_data else "N/A")
            matched_peer = matched_peer_by_nb_id.get(nb_dev["id"])
            if matched_peer:
                wg_name_val = matched_peer["name"] or "-"
                hs_val = (
                    "disabled"
                    if matched_peer["disabled"]
                    else format_duration_human(matched_peer["last_handshake_sec"])
                )
            else:
                wg_name_val = "-"
                hs_val = "-"

            issue_reasons = []
            if ox_tag_lower not in nb_dev["tags"]:
                issue_reasons.append(f"brak tagu '{OXIDIZED_TAG_NAME}'")
            if nb_dev["platform_slug"] not in ("routeros", "mikrotik-routeros"):
                issue_reasons.append(f"platforma='{nb_dev['platform_slug'] or 'BRAK'}'")
            if ox_data and ox_tag_lower in nb_dev["tags"]:
                if not ox_node:
                    issue_reasons.append("nieobecny w /nodes.json (zrób /reload)")
                elif ox_node["last_status"] != "success":
                    issue_reasons.append(f"Oxidized last_status='{ox_node['last_status']}'")

            if issue_reasons:
                oxidized_issues.append(
                    {
                        "bucket": "5_OXIDIZED_METADATA_OR_BACKUP_ISSUE",
                        "wg_ip": nb_dev["primary_ip"],
                        "wg_name": wg_name_val,
                        "serial": nb_dev["serial"],
                        "handshake": hs_val,
                        "netbox_name": nb_dev["name"],
                        "netbox_status": nb_dev["status"],
                        "oxidized_status": ox_state,
                        "action": "; ".join(issue_reasons),
                    }
                )

    return {
        "missing_in_netbox": missing_in_netbox,
        "active_not_active_in_netbox": active_not_active_in_netbox,
        "stale_or_disabled": stale_or_disabled,
        "netbox_orphans": netbox_orphans,
        "oxidized_issues": oxidized_issues,
    }


def print_bucket(title, rows):
    print(f"\n=== {title} ({len(rows)}) ===")
    if not rows:
        print("  (brak rozjazdów)")
        return
    for r in rows:
        print(
            f"  - IP: {r['wg_ip'] or '-':<15} | WG: {r['wg_name']:<32} | "
            f"SN: {r['serial'] or '-':<12} | HS: {r['handshake']:<9} | "
            f"NB: {r['netbox_name']} [{r['netbox_status']}] | {r['action']}"
        )


def write_csv_report(csv_path, results):
    fieldnames = [
        "bucket", "wg_ip", "wg_name", "serial", "handshake",
        "netbox_name", "netbox_status", "oxidized_status", "action",
    ]
    all_rows = (
        results["missing_in_netbox"]
        + results["active_not_active_in_netbox"]
        + results["stale_or_disabled"]
        + results["netbox_orphans"]
        + results["oxidized_issues"]
    )
    with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)
    print(f"\n[✓] Zapisano raport CSV ({len(all_rows)} wpisów): {csv_path}")


def read_text_auto_encoding(filepath):
    """Wczytuje plik tekstowy niezależnie od kodowania (UTF-8, UTF-8-BOM, UTF-16 z PowerShell/Windows)."""
    with open(filepath, "rb") as f:
        raw = f.read()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="ignore")
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", errors="ignore")
    if b"\x00" in raw[:200]:
        return raw.decode("utf-16-le", errors="ignore")
    return raw.decode("utf-8", errors="ignore")


def main():
    parser = argparse.ArgumentParser(
        description="Audyt 3-Way Reconciliation (Read-Only): WireGuard Peers vs NetBox SoT vs Oxidized."
    )
    parser.add_argument(
        "peers_file",
        help="Plik tekstowy ze zrzutem '/interface/wireguard/peers/print terse ...' z Core Routera.",
    )
    parser.add_argument(
        "--stale-days",
        type=int,
        default=7,
        help="Próg dni uznania last-handshake za nieaktywny (domyślnie: 7).",
    )
    parser.add_argument(
        "--oxidized-url",
        default=OXIDIZED_URL,
        help="Opcjonalny adres Oxidized Web UI (np. http://127.0.0.1:8888) do weryfikacji /nodes.json.",
    )
    parser.add_argument(
        "--csv",
        dest="csv_path",
        default="",
        help="Opcjonalna ścieżka zapisu zbiorczego raportu CSV.",
    )
    args = parser.parse_args()

    if not os.path.exists(args.peers_file):
        print(f"[X] Nie znaleziono pliku: {args.peers_file}")
        sys.exit(1)

    raw_text = read_text_auto_encoding(args.peers_file)

    nb = init_netbox()
    mgmt_networks = fetch_global_mgmt_networks(nb)
    peers = parse_wg_peers_terse(raw_text, mgmt_networks)
    if not peers:
        preview = repr(raw_text[:160])
        print(
            f"[X] Sparsowano 0 peerów z pliku '{args.peers_file}'! "
            f"Sprawdź zawartość pliku (pierwsze znaki: {preview})."
        )
        sys.exit(1)
    nb_inv = fetch_netbox_inventory(nb, mgmt_networks)
    ox_data = fetch_oxidized_nodes(args.oxidized_url)

    results = reconcile(peers, nb_inv, ox_data, stale_days=args.stale_days)

    print("=" * 78)
    print(
        f"PODSUMOWANIE AUDYTU | WG Peers: {len(peers)} | "
        f"NetBox MGMT IPs: {len(nb_inv['by_mgmt_ip'])} | "
        f"Oxidized Nodes: {ox_data['count'] if ox_data else 'pominięto'}"
    )
    print("=" * 78)

    print_bucket("1. AKTYWNE NA WG, BRAK W NETBOXIE (Do dodania przez --only-new)", results["missing_in_netbox"])
    print_bucket("2. AKTYWNE NA WG, ZŁY STATUS W NETBOXIE (np. staged -> active)", results["active_not_active_in_netbox"])
    print_bucket(f"3. MARTWE / STARE (> {args.stale_days}d) LUB DISABLED NA WG", results["stale_or_disabled"])
    print_bucket("4. SIEROTY W NETBOXIE (active z IP WG, brak na Core Routerze)", results["netbox_orphans"])
    print_bucket("5. PROBLEMY OXIDIZED (brak tagu/platformy lub błąd backupu)", results["oxidized_issues"])

    if args.csv_path:
        write_csv_report(args.csv_path, results)


if __name__ == "__main__":
    main()
