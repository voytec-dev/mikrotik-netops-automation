import argparse
import glob
import ipaddress
import os
import re
import shutil
import sys
import pynetbox
from dotenv import load_dotenv

load_dotenv()


def env_bool(name, default=False):
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


# =====================================================================
# 1. KONFIGURACJA POŁĄCZENIA I ZACHOWANIA SKRYPTU
# =====================================================================
NETBOX_URL = os.getenv("NETBOX_URL", "http://netbox.local:8000")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN", "")
NETBOX_VERIFY_SSL = env_bool("NETBOX_VERIFY_SSL", True)

# Czy przenosić przetworzone pliki do podkatalogu archiwum?
ARCHIVE_IMPORTED_FILES = env_bool("ARCHIVE_IMPORTED_FILES", True)
ARCHIVE_DIR_NAME = os.getenv("ARCHIVE_DIR_NAME", "zaimportowane")

# Czy usuwać z urządzenia w NetBoxie stare adresy IP i wycofane interfejsy wirtualne?
CLEANUP_REMOVED_IPS = env_bool("CLEANUP_REMOVED_IPS", True)
CLEANUP_REMOVED_VIRTUAL_INTERFACES = env_bool("CLEANUP_REMOVED_VIRTUAL_INTERFACES", True)

# Nazwa roli w NetBoxie identyfikującej globalną sieć zarządzania (np. WireGuard do Core Routera / systemu zarządzania)
MGMT_VPN_ROLE_NAME = os.getenv("MGMT_VPN_ROLE_NAME", "Wireguard Management")
FALLBACK_MGMT_SUPERNET = ipaddress.ip_network(os.getenv("FALLBACK_MGMT_SUPERNET", "10.0.0.0/22"))

# Automatyczne metadane pod Oxidized i dynamiczne inventory Ansible
AUTO_SET_PLATFORM = env_bool("AUTO_SET_PLATFORM", True)
AUTO_TAG_OXIDIZED = env_bool("AUTO_TAG_OXIDIZED", True)
OXIDIZED_TAG_NAME = os.getenv("OXIDIZED_TAG_NAME", "oxidized")
OXIDIZED_TAG_REQUIRE_MGMT_IP = env_bool("OXIDIZED_TAG_REQUIRE_MGMT_IP", True)

nb = None
GLOBAL_MGMT_NETWORKS = []

# Pamięć podręczna typów urządzeń z NetBoxa (ładowana raz przy starcie)
DEVICE_TYPES_CACHE = None


# =====================================================================
# 2. BEZPIECZNE FUNKCJE POMOCNICZE NETBOX I FORMATOWANIE OPISÓW
# =====================================================================
def safe_desc(text, max_len=195):
    """Gwarantuje, że żaden opis nie przekroczy limitu 200 znaków w bazie NetBoxa."""
    if not text:
        return ""
    text = str(text).strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 3].rstrip(" ,;-") + "..."


def short_dev_label(dev_name):
    """Skraca pełną nazwę urządzenia (np. 'ACME_BRANCH-A_R01' -> 'Branch-A')."""
    short = dev_name.split("_", 1)[1] if "_" in dev_name else dev_name
    short = re.sub(
        r"([-_](R\d*|RTR\d*|ROUTER\d*|SW\d*|SWITCH\d*|CORE|POE|CSS\d*|CRS\d*|FR))+\b",
        "",
        short,
        flags=re.I,
    ).strip("-_")
    if not short:
        short = dev_name
    return short.title() if short.isupper() else short


def normalize_device_base_identity(dev_name):
    """
    Sprowadza nazwę urządzenia do rdzenia roli (np. 'CLIENT-A_SITE-01-R' oraz 'CLIENT-A_SITE-01-R01' -> 'CLIENT-A_SITE-01-R'),
    co pozwala wykryć zmianę nazwy tego samego routera/switcha w oddziale.
    """
    s = dev_name.strip().upper()
    s = re.sub(r"[-_](R|RTR|ROUTER)0*\d*$", "-R", s)
    s = re.sub(r"[-_](SW|SWITCH)0*(\d+)$", r"-SW\2", s)
    return s


def make_slug(text):
    slug = text.lower()
    replacements = {
        "ą": "a", "ć": "c", "ę": "e", "ł": "l",
        "ń": "n", "ó": "o", "ś": "s", "ź": "z", "ż": "z",
    }
    for pl, ascii_char in replacements.items():
        slug = slug.replace(pl, ascii_char)
    return re.sub(r"[^a-z0-9]+", "-", slug).strip("-")


def safe_first(endpoint, **kwargs):
    try:
        results = list(endpoint.filter(**kwargs))
        return results[0] if results else None
    except Exception:
        return None


def find_by_name_or_slug(endpoint, name=None, slug=None):
    if name:
        obj = safe_first(endpoint, name=name)
        if obj:
            return obj
    if slug:
        obj = safe_first(endpoint, slug=slug)
        if obj:
            return obj
    if name:
        for item in endpoint.filter(q=name):
            if getattr(item, "name", "").lower() == name.lower():
                return item
            if slug and getattr(item, "slug", "") == slug:
                return item
    return None


def get_or_create_role(role_name):
    if not role_name:
        return None
    slug = make_slug(role_name)
    role = find_by_name_or_slug(nb.ipam.roles, name=role_name, slug=slug)
    if not role:
        role = nb.ipam.roles.create(name=role_name, slug=slug)
    return role


def get_global_mgmt_networks():
    nets = []
    role = find_by_name_or_slug(
        nb.ipam.roles, name=MGMT_VPN_ROLE_NAME, slug=make_slug(MGMT_VPN_ROLE_NAME)
    )
    if role:
        for p in nb.ipam.prefixes.filter(role_id=role.id):
            if getattr(p, "vrf", None) is None:
                try:
                    nets.append(ipaddress.ip_network(p.prefix, strict=False))
                except Exception:
                    pass
    if not nets:
        nets.append(FALLBACK_MGMT_SUPERNET)
    return nets


def init_netbox():
    """Inicjalizuje połączenie z REST API NetBox oraz pobiera globalne sieci zarządzania."""
    global nb, GLOBAL_MGMT_NETWORKS
    if nb is not None:
        return nb
    if not NETBOX_TOKEN:
        print("[X] Brak zmiennej NETBOX_TOKEN. Skopiuj .env.example do .env i uzupełnij dane dostępowe.")
        sys.exit(1)
    nb = pynetbox.api(NETBOX_URL, token=NETBOX_TOKEN)
    nb.http_session.verify = NETBOX_VERIFY_SSL
    GLOBAL_MGMT_NETWORKS = get_global_mgmt_networks()
    return nb


def match_global_mgmt_network(ip_obj):
    for net in GLOBAL_MGMT_NETWORKS:
        if ip_obj in net:
            return net
    return None


def expand_vlan_ids(vlan_ids_str):
    vids = []
    for part in str(vlan_ids_str).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start_v, end_v = part.split("-", 1)
                vids.extend(range(int(start_v), int(end_v) + 1))
            except ValueError:
                pass
        else:
            try:
                vids.append(int(part))
            except ValueError:
                pass
    return vids


def safe_reassign_ip_to_interface(nb_ip, target_iface, target_device, new_address_str=None, new_tenant_id=None, new_desc=None):
    """
    Bezpiecznie przypisuje istniejący adres IP do docelowego interfejsu.
    Jeśli adres IP był wcześniej oznaczony jako Primary IPv4 na INNYM urządzeniu (np. przed zmianą nazwy
    lub po duplikacji urządzenia), najpierw zdejmuje blokadę primary_ip4 ze starego urządzenia,
    aby uniknąć błędu 400: 'Cannot reassign IP address while it is designated as the primary IP for the parent object'.
    """
    old_iface_id = getattr(nb_ip, "assigned_object_id", None)
    if old_iface_id and old_iface_id != target_iface.id:
        try:
            old_iface = nb.dcim.interfaces.get(old_iface_id)
            old_dev_id = getattr(getattr(old_iface, "device", None), "id", None)
            if old_dev_id and old_dev_id != target_device.id:
                old_dev = nb.dcim.devices.get(old_dev_id)
                if old_dev and getattr(getattr(old_dev, "primary_ip4", None), "id", None) == nb_ip.id:
                    print(f"[~] Zwalniam blokadę Primary IPv4 ({nb_ip.address}) ze starego obiektu: {old_dev.name}")
                    old_dev.primary_ip4 = None
                    old_dev.save()
        except Exception:
            pass

    # Sprawdź również czy jakiekolwiek inne urządzenie w NetBoxie nie trzyma tego IP jako primary_ip4
    if old_iface_id != target_iface.id:
        try:
            for d in nb.dcim.devices.filter(primary_ip4_id=nb_ip.id):
                if d.id != target_device.id:
                    d.primary_ip4 = None
                    d.save()
        except Exception:
            pass

    changed = False
    if new_address_str and nb_ip.address != new_address_str:
        print(f"[~] Poprawiam maskę IP z {nb_ip.address} na {new_address_str}")
        nb_ip.address = new_address_str
        changed = True
    if new_tenant_id and getattr(nb_ip.tenant, "id", None) != new_tenant_id:
        nb_ip.tenant = new_tenant_id
        changed = True
    if new_desc and getattr(nb_ip, "description", "") != new_desc:
        nb_ip.description = new_desc
        changed = True
    if getattr(nb_ip, "assigned_object_type", None) != "dcim.interface" or getattr(nb_ip, "assigned_object_id", None) != target_iface.id:
        nb_ip.assigned_object_type = "dcim.interface"
        nb_ip.assigned_object_id = target_iface.id
        changed = True

    if changed:
        nb_ip.save()


# =====================================================================
# 3. UNIWERSALNA KLASYFIKACJA RÓL PODSIECI, TUNELI I URZĄDZEŃ
# =====================================================================
def count_roadwarrior_peers(if_name, parsed):
    if_peers = [p for p in parsed.get("wg_peers", []) if p["interface"] == if_name]
    rw_count = 0
    for p in if_peers:
        allowed = [a.strip() for a in p.get("allowed_address", "").split(",") if a.strip()]
        has_subnet_behind = any(not a.endswith("/32") for a in allowed)
        if not has_subnet_behind and not p.get("endpoint"):
            rw_count += 1
    return rw_count


def classify_vpn_type(network_str, if_name, parsed):
    if_lower = if_name.lower()
    is_vpn_if = (
        if_name in parsed.get("vpn_interfaces", set())
        or if_lower.startswith(("wg", "wireguard", "ovpn", "sstp", "l2tp", "gre", "eoip", "ipsec"))
    )

    if not is_vpn_if:
        return None

    net = None
    if network_str:
        try:
            net = ipaddress.ip_network(network_str, strict=False)
        except ValueError:
            net = None

    if net and net.prefixlen in (30, 31):
        return "Site-to-Site VPN"

    if any(k in if_lower for k in ("s2s", "site")):
        return "Site-to-Site VPN"
    if any(k in if_lower for k in ("user", "client", "roadwarrior")):
        return "VPN / Zdalny Dostęp"

    if_peers = [p for p in parsed.get("wg_peers", []) if p["interface"] == if_name]
    if if_peers:
        has_site_peers = False
        has_roadwarrior_peers = False

        for p in if_peers:
            allowed = [a.strip() for a in p.get("allowed_address", "").split(",") if a.strip()]
            has_subnet_behind = any(not a.endswith("/32") for a in allowed)
            if has_subnet_behind or p.get("endpoint"):
                has_site_peers = True
            else:
                has_roadwarrior_peers = True

        if has_site_peers:
            return "Site-to-Site VPN"
        if has_roadwarrior_peers:
            return "VPN / Zdalny Dostęp"

    return "Site-to-Site VPN"


def is_oob_service_subnet(network_str="", if_name="", comment=""):
    text = f"{if_name} {comment}".lower()
    if ".59." in network_str or "192.168.88." in network_str:
        return True
    if any(k in text for k in ("oob", "serwis", "service", "awaryjn")):
        return True
    if re.match(r"^ether\d+[-_]?mgmt$", if_name.lower()):
        return True
    return False


def zgadnij_role_podsieci(vid=None, network_str="", if_name="", comment="", parsed=None):
    text = f"{if_name} {comment}".lower()
    parsed = parsed or {}

    vpn_role = classify_vpn_type(network_str, if_name, parsed)
    if vpn_role:
        return vpn_role

    if if_name in parsed.get("wan_interfaces", set()) or "wan" in if_name.lower() or "isp" in text:
        return "WAN / ISP"

    if is_oob_service_subnet(network_str, if_name, comment):
        return "Serwis Lokalny"

    if (
        if_name in parsed.get("mgmt_interfaces", set())
        or any(k in text for k in ("mgmt", "zarzadz", "admin", "manage"))
        or vid in (50, 255)
    ):
        return "Management"

    if any(k in text for k in ("cctv", "kamera", "kamery", "ideo", "monitoring", "nvr")) or vid in (2, 101, 105, 110):
        return "CCTV / Monitoring"
    if any(k in text for k in ("guest", "gosc", "gość", "free", "public")) or vid == 199:
        return "Wi-Fi Goście"
    if any(k in text for k in ("voip", "sip", "telef", "pbx")) or vid == 254:
        return "VoIP / Telefonia"
    if any(
        k in text
        for k in ("rcp", "iot", "alarm", "automatyka", "czujnik", "produkcja", "klima", "kd", "magicinfo", "tv", "drukark", "print")
    ) or vid in (3, 48, 80, 155, 201, 205):
        return "IoT / RCP / Automatyka"

    if (
        if_name in parsed.get("lan_interfaces", set())
        or any(
            k in text
            for k in (
                "local", "lan", "biuro", "office", "bridge", "dom", "sklep", "firma",
                "srv", "serwer", "vm", "kadry", "ksiegow", "apteka", "butik", "magazyn", "wifi", "piekarnia", "sasiad"
            )
        )
        or vid in (5, 10, 20, 30, 100, 150, 250, 300, 350, 1001, 1002, 1010)
    ):
        return "LAN / Biuro"

    if network_str:
        try:
            net = ipaddress.ip_network(network_str, strict=False)
            if net.is_private and net.prefixlen <= 29:
                return "LAN / Biuro"
        except ValueError:
            pass

    return None


def okresl_role_urzadzenia(model_name, identity, ips, is_router):
    if is_router:
        return "Router"
    id_upper = identity.upper()
    model_upper = model_name.upper()
    if any(k in id_upper for k in ("-CORE", "_CORE", "-AGR", "-DIST")):
        return "Core Switch"
    if any(m in model_upper for m in ("CRS309", "CRS317", "CRS312", "CRS326-24S+2Q+")):
        return "Core Switch"
    for ip in ips:
        if ".50.10/" in ip.get("address", ""):
            return "Core Switch"
    return "Switch"


def calculate_ip_priority(ip_iface, if_name, role_name, is_router):
    network_str = str(ip_iface.network)
    if match_global_mgmt_network(ip_iface.ip):
        return 100
    if is_oob_service_subnet(network_str, if_name, ""):
        return 10
    if role_name == "Management" or "vlan50" in if_name.lower() or ".50." in network_str:
        return 90
    if role_name == "LAN / Biuro":
        return 80
    if role_name in ("WAN / ISP", "Site-to-Site VPN", "VPN / Zdalny Dostęp"):
        return 50
    return 60


# =====================================================================
# 4. UNIWERSALNE DOPASOWANIE I BUDOWANIE DEVICE TYPE (BEZ SZTYWNYCH LIST)
# =====================================================================
def get_all_device_types_cached():
    global DEVICE_TYPES_CACHE
    if DEVICE_TYPES_CACHE is None:
        DEVICE_TYPES_CACHE = list(nb.dcim.device_types.all())
    return DEVICE_TYPES_CACHE


def invalidate_device_types_cache():
    global DEVICE_TYPES_CACHE
    DEVICE_TYPES_CACHE = None


def normalize_hw_code(code_str):
    if not code_str:
        return ""
    s = code_str.strip().upper()
    s_base = re.sub(r"[-+]?(IN|RM|OUT|PC|TC|2HND|2ND)(-IN|-RM)?$", "", s)
    return s_base.strip("-+_ ") or s


def has_interface_templates(dev_type_obj):
    if not dev_type_obj:
        return False
    try:
        cnt = getattr(dev_type_obj, "interface_template_count", None)
        if cnt is not None:
            return cnt > 0
        return len(list(nb.dcim.interface_templates.filter(device_type_id=dev_type_obj.id))) > 0
    except Exception:
        return False


def infer_hardware_ports_from_parsed(parsed):
    if not parsed:
        return []

    if parsed.get("ext") == ".swb" and parsed.get("swos_ports"):
        return [(sp["default_name"], sp["type"]) for sp in parsed["swos_ports"]]

    max_ether = 0
    max_sfpplus = 0
    max_sfp = 0
    has_single_sfp = False
    has_combo = False

    all_if_references = (
        set(parsed.get("ethernets", {}).keys())
        | {v.get("default_name", "") for v in parsed.get("ethernets", {}).values()}
        | set(parsed.get("bridge_ports", {}).keys())
        | set(parsed.get("all_mentioned_ports", set()))
        | set(parsed.get("wan_interfaces", set()))
    )
    for bv in parsed.get("bridge_vlans", []):
        all_if_references |= bv.get("tagged", set()) | bv.get("untagged", set())

    for ref in all_if_references:
        low = ref.lower()
        m_eth = re.match(r"^ether(\d+)(?:$|[-_])", low)
        if m_eth:
            max_ether = max(max_ether, int(m_eth.group(1)))

        m_sfpp = re.match(r"^sfp-sfpplus(\d+)(?:$|[-_])", low)
        if m_sfpp:
            max_sfpplus = max(max_sfpplus, int(m_sfpp.group(1)))

        m_sfp = re.match(r"^sfp(\d+)(?:$|[-_])", low)
        if m_sfp:
            num = int(m_sfp.group(1))
            if "+" in parsed.get("model", ""):
                max_sfpplus = max(max_sfpplus, num)
            else:
                max_sfp = max(max_sfp, num)

        if low == "sfp1" or low.startswith(("sfp1_", "sfp1-", "sfp-trunk")):
            if "+" in parsed.get("model", ""):
                max_sfpplus = max(max_sfpplus, 1)
            else:
                has_single_sfp = True
        if low.startswith("combo"):
            has_combo = True

    model_up = parsed.get("model", "").upper()
    m_24g = re.search(r"(\d+)G", model_up)
    if m_24g and max_ether < int(m_24g.group(1)) <= 48:
        max_ether = int(m_24g.group(1))
    m_sfp_model = re.search(r"(\d+)S\+", model_up)
    if m_sfp_model and max_sfpplus < int(m_sfp_model.group(1)) <= 32:
        max_sfpplus = int(m_sfp_model.group(1))

    layout = []
    for i in range(1, max_ether + 1):
        layout.append((f"ether{i}", "1000base-t"))
    if has_combo:
        layout.append(("combo1", "1000base-t"))
    if has_single_sfp and max_sfp == 0 and max_sfpplus == 0:
        layout.append(("sfp1", "1000base-x-sfp"))
    for i in range(1, max_sfp + 1):
        layout.append((f"sfp{i}", "1000base-x-sfp"))
    for i in range(1, max_sfpplus + 1):
        layout.append((f"sfp-sfpplus{i}", "10gbase-x-sfpp"))

    return layout


def ensure_device_type_templates(dev_type_obj, parsed=None):
    if has_interface_templates(dev_type_obj):
        return
    layout = infer_hardware_ports_from_parsed(parsed)
    if not layout:
        return
    print(f"[+] Automatycznie buduję szablon portów ({len(layout)} portów) dla typu: {dev_type_obj.model}")
    for port_name, port_type in layout:
        try:
            nb.dcim.interface_templates.create(
                device_type=dev_type_obj.id,
                name=port_name,
                type=port_type,
            )
        except Exception:
            pass
    invalidate_device_types_cache()


def find_or_create_best_device_type(default_mfg, model_name, parsed=None):
    raw_up = model_name.strip().upper()
    norm_target = normalize_hw_code(model_name)
    all_dts = get_all_device_types_cached()

    matched_candidates = []
    for dt in all_dts:
        dt_model = (getattr(dt, "model", "") or "").strip().upper()
        dt_part = (getattr(dt, "part_number", "") or "").strip().upper()

        if raw_up in (dt_model, dt_part):
            matched_candidates.append((100, dt))
            continue

        norm_dt_model = normalize_hw_code(dt_model)
        norm_dt_part = normalize_hw_code(dt_part)
        if norm_target and norm_target in (norm_dt_model, norm_dt_part):
            matched_candidates.append((90, dt))
            continue

    if matched_candidates:
        matched_candidates.sort(
            key=lambda item: (
                1 if has_interface_templates(item[1]) else 0,
                item[0],
                getattr(item[1], "device_count", 0) or 0,
            ),
            reverse=True,
        )
        best_dt = matched_candidates[0][1]
        ensure_device_type_templates(best_dt, parsed=parsed)

        for _, other_dt in matched_candidates[1:]:
            if other_dt.id != best_dt.id and (getattr(other_dt, "device_count", 0) or 0) == 0 and not has_interface_templates(other_dt):
                try:
                    other_dt.delete()
                    invalidate_device_types_cache()
                except Exception:
                    pass
        return best_dt

    model_slug = make_slug(model_name)
    print(f"[+] Rejestruję nowy typ urządzenia w bazie NetBox: {model_name}")
    new_dt = nb.dcim.device_types.create(
        manufacturer=default_mfg.id,
        model=model_name,
        part_number=model_name,
        slug=model_slug,
    )
    invalidate_device_types_cache()
    ensure_device_type_templates(new_dt, parsed=parsed)
    return new_dt


# =====================================================================
# 4B. POZOSTAŁE OBIEKTY NETBOX (TENANT, VRF, SITE, VLAN GROUP, DEVICE)
# =====================================================================
def get_or_create_tenant(tenant_name):
    slug = make_slug(tenant_name)
    tenant = find_by_name_or_slug(nb.tenancy.tenants, name=tenant_name, slug=slug)
    if not tenant:
        print(f"[+] Tworzę klienta (Tenant): {tenant_name}")
        tenant = nb.tenancy.tenants.create(name=tenant_name, slug=slug)
    return tenant


def get_or_create_vrf(tenant):
    vrf = safe_first(nb.ipam.vrfs, name=tenant.name, tenant_id=tenant.id) or safe_first(
        nb.ipam.vrfs, name=tenant.name
    )
    if not vrf:
        print(f"[+] Tworzę VRF: {tenant.name}")
        vrf = nb.ipam.vrfs.create(
            name=tenant.name, tenant=tenant.id, enforce_unique=False
        )
    elif getattr(vrf, "enforce_unique", False):
        print(f"[~] Aktualizuję VRF {vrf.name}: wyłączam enforce_unique (obsługa powtarzalnych podsieci lokalnych)")
        vrf.enforce_unique = False
        vrf.save()
    return vrf


def ensure_client_container_prefix(vrf, tenant, ip_iface):
    ip_str = str(ip_iface.ip)
    if ip_str.startswith("172.") or ip_str.startswith("10."):
        octets = ip_str.split(".")
        if ip_str.startswith("10.") and int(octets[1]) in (0, 1, 250, 255):
            return
        container_str = f"{octets[0]}.{octets[1]}.0.0/16"
        if not safe_first(nb.ipam.prefixes, prefix=container_str, vrf_id=vrf.id):
            parent_role = get_or_create_role("Pula Główna Klienta")
            print(f"[+] Tworzę kontener nadrzędny {container_str} w VRF {vrf.name}")
            nb.ipam.prefixes.create(
                prefix=container_str,
                vrf=vrf.id,
                tenant=tenant.id,
                status="container",
                role=parent_role.id if parent_role else None,
                description=safe_desc(f"Główna pula adresowa ({tenant.name})"),
            )


def get_or_create_site(tenant, site_name):
    full_site_name = (
        f"{tenant.name} - {site_name}"
        if site_name.lower() in ("glowna", "główna", "main")
        else site_name
    )
    slug = make_slug(f"{tenant.name}-{site_name}")

    site = find_by_name_or_slug(nb.dcim.sites, name=full_site_name, slug=slug)
    if not site:
        existing = find_by_name_or_slug(nb.dcim.sites, name=site_name)
        if existing and getattr(existing.tenant, "id", None) == tenant.id:
            return existing
        elif existing:
            full_site_name = f"{tenant.name} - {site_name}"

        print(f"[+] Tworzę lokalizację (Site): {full_site_name}")
        site = nb.dcim.sites.create(name=full_site_name, slug=slug, tenant=tenant.id)
    return site


def get_or_create_vlan_group(site, tenant):
    group_name = f"VLANs - {site.name}"
    slug = make_slug(f"vlans-{site.slug}")
    vg = find_by_name_or_slug(nb.ipam.vlan_groups, name=group_name, slug=slug)
    if not vg:
        existing_by_scope = safe_first(nb.ipam.vlan_groups, scope_id=site.id)
        if existing_by_scope:
            return existing_by_scope

        vg = nb.ipam.vlan_groups.create(
            name=group_name,
            slug=slug,
            scope_type="dcim.site",
            scope_id=site.id,
            tenant=tenant.id,
        )
    return vg


def instantiate_templates_for_existing_device(device, dev_type, parsed=None):
    try:
        templates = list(nb.dcim.interface_templates.filter(device_type_id=dev_type.id))
        if not templates:
            return
        existing_ifaces = list(nb.dcim.interfaces.filter(device_id=device.id))
        existing_if_names = {i.name for i in existing_ifaces}
        existing_if_labels = {getattr(i, "label", "") for i in existing_ifaces if getattr(i, "label", "")}

        renamed_default_names = set()
        if parsed:
            for eth_info in parsed.get("ethernets", {}).values():
                if eth_info.get("default_name") and eth_info.get("name") in existing_if_names:
                    renamed_default_names.add(eth_info["default_name"])

        for tmpl in templates:
            if (
                tmpl.name not in existing_if_names
                and tmpl.name not in existing_if_labels
                and tmpl.name not in renamed_default_names
            ):
                t_type = getattr(tmpl.type, "value", "1000base-t")
                nb.dcim.interfaces.create(
                    device=device.id,
                    name=tmpl.name,
                    type=t_type,
                )
    except Exception:
        pass


def merge_and_cleanup_duplicate_device(old_dev, target_dev):
    """
    Jeśli wskutek zmiany nazwy (np. CLIENT-A_SITE-01-R -> CLIENT-A_SITE-01-R01) w bazie powstały dwa obiekty,
    zwalnia Primary IP oraz przenosi kable/zakończenia tuneli ze starego duplikatu i bezpiecznie go usuwa.
    """
    if old_dev.id == target_dev.id:
        return
    print(f"[~] Scalam i usuwam zduplikowany stary obiekt urządzenia: {old_dev.name} -> {target_dev.name}")
    try:
        if getattr(old_dev, "primary_ip4", None):
            old_dev.primary_ip4 = None
            old_dev.save()
        for old_if in nb.dcim.interfaces.filter(device_id=old_dev.id):
            for ip_obj in nb.ipam.ip_addresses.filter(assigned_object_id=old_if.id):
                ip_obj.assigned_object_type = None
                ip_obj.assigned_object_id = None
                ip_obj.save()
        old_dev.delete()
    except Exception as e:
        print(f"      [!] Ostrzeżenie podczas usuwania starego duplikatu {old_dev.name}: {e}")


def get_or_create_platform(ext, default_mfg):
    """Zwraca lub tworzy platformę NetBox (routeros dla .rsc, swos dla .swb)."""
    if ext == ".swb":
        name, slug = "MikroTik SwOS", "swos"
    else:
        name, slug = "MikroTik RouterOS", "routeros"
    platform = find_by_name_or_slug(nb.dcim.platforms, name=name, slug=slug)
    if not platform:
        print(f"[+] Tworzę platformę (Platform): {name} ({slug})")
        platform = nb.dcim.platforms.create(
            name=name, slug=slug, manufacturer=default_mfg.id
        )
    return platform


def get_or_create_tag(tag_name, color="009688"):
    """Zwraca lub tworzy tag NetBox (np. 'oxidized')."""
    slug = make_slug(tag_name)
    tag = find_by_name_or_slug(nb.extras.tags, name=tag_name, slug=slug)
    if not tag:
        print(f"[+] Tworzę tag NetBox: {tag_name}")
        tag = nb.extras.tags.create(name=tag_name, slug=slug, color=color)
    return tag


def ensure_device_tag(device, tag_obj):
    """Idempotentnie dopisuje tag do urządzenia bez nadpisywania istniejących tagów."""
    if not tag_obj:
        return
    existing_tags = list(getattr(device, "tags", None) or [])
    existing_ids = set()
    serialized_tags = []
    for t in existing_tags:
        t_id = getattr(t, "id", None) if not isinstance(t, dict) else t.get("id")
        t_name = getattr(t, "name", None) if not isinstance(t, dict) else t.get("name")
        t_slug = getattr(t, "slug", None) if not isinstance(t, dict) else t.get("slug")
        if t_id:
            existing_ids.add(t_id)
            serialized_tags.append({"id": t_id, "name": t_name, "slug": t_slug})
    if tag_obj.id in existing_ids:
        return
    serialized_tags.append({"id": tag_obj.id, "name": tag_obj.name, "slug": tag_obj.slug})
    try:
        device.tags = serialized_tags
        device.save()
        print(f"[~] Przypisano tag '{tag_obj.name}' do urządzenia: {device.name}")
    except Exception as e:
        print(f"      [!] Ostrzeżenie podczas przypisywania tagu '{tag_obj.name}' do {device.name}: {e}")


def get_or_create_device(device_name, model_name, serial, site, tenant, role_name="Router", parsed=None):
    default_mfg = find_by_name_or_slug(nb.dcim.manufacturers, name="MikroTik", slug="mikrotik")
    if not default_mfg:
        default_mfg = nb.dcim.manufacturers.create(name="MikroTik", slug="mikrotik")

    role_slug = make_slug(role_name)
    color = "f44336" if role_name == "Router" else ("607d8b" if role_name == "Core Switch" else "2196f3")
    dev_role = find_by_name_or_slug(nb.dcim.device_roles, name=role_name, slug=role_slug)
    if not dev_role:
        dev_role = nb.dcim.device_roles.create(
            name=role_name, slug=role_slug, color=color
        )

    dev_type = find_or_create_best_device_type(default_mfg, model_name, parsed=parsed)
    platform_obj = (
        get_or_create_platform(parsed.get("ext", ".rsc"), default_mfg)
        if (AUTO_SET_PLATFORM and parsed)
        else None
    )

    # 1. Szukaj po dokładnej nazwie oraz po numerze seryjnym
    dev_by_name = safe_first(nb.dcim.devices, name=device_name)
    dev_by_serial = safe_first(nb.dcim.devices, serial=serial) if serial else None

    # 2. Szukaj po znormalizowanym rdzeniu nazwy w tym samym Site (np. CLIENT-A_SITE-01-R vs CLIENT-A_SITE-01-R01)
    norm_my_id = normalize_device_base_identity(device_name)
    dev_by_norm = None
    for s_dev in nb.dcim.devices.filter(site_id=site.id):
        if s_dev.name != device_name and normalize_device_base_identity(s_dev.name) == norm_my_id:
            dev_by_norm = s_dev
            break

    old_counterpart = dev_by_serial or dev_by_norm

    # Jeśli istnieją OBA (bo poprzednie uruchomienie zdążyło utworzyć nowy obiekt obok starego), scal je!
    if dev_by_name and old_counterpart and dev_by_name.id != old_counterpart.id:
        merge_and_cleanup_duplicate_device(old_counterpart, dev_by_name)
        device = dev_by_name
    elif not dev_by_name and old_counterpart:
        print(f"[~] Wykryto zmianę nazwy urządzenia w {site.name}: {old_counterpart.name} -> {device_name}")
        device = old_counterpart
        device.name = device_name
        device.save()
    else:
        device = dev_by_name

    if not device:
        print(f"[+] Dodaję urządzenie: {device_name} (Typ: {dev_type.model}, Rola: {role_name})")
        device = nb.dcim.devices.create(
            name=device_name,
            device_type=dev_type.id,
            role=dev_role.id,
            platform=platform_obj.id if platform_obj else None,
            site=site.id,
            tenant=tenant.id,
            serial=serial or "",
            status="active",
        )
    else:
        changed = False
        old_dt_id = getattr(device.device_type, "id", None)
        if old_dt_id != dev_type.id:
            print(f"[~] Zmieniam Device Type dla {device_name}: {getattr(device.device_type, 'model', '')} -> {dev_type.model}")
            device.device_type = dev_type.id
            changed = True
        if getattr(device.role, "id", None) != dev_role.id:
            device.role = dev_role.id
            changed = True
        if getattr(device.site, "id", None) != site.id:
            device.site = site.id
            changed = True
        if serial and getattr(device, "serial", "") != serial:
            device.serial = serial
            changed = True
        if platform_obj and getattr(device.platform, "id", None) != platform_obj.id:
            device.platform = platform_obj.id
            changed = True
        if changed:
            device.save()
            if old_dt_id != dev_type.id:
                instantiate_templates_for_existing_device(device, dev_type, parsed=parsed)
                try:
                    old_dt = nb.dcim.device_types.get(old_dt_id)
                    if old_dt and (getattr(old_dt, "device_count", 0) or 0) == 0 and not has_interface_templates(old_dt):
                        old_dt.delete()
                        invalidate_device_types_cache()
                except Exception:
                    pass
        else:
            instantiate_templates_for_existing_device(device, dev_type, parsed=parsed)

    return device


def get_prefix_site_id(prefix_obj):
    if getattr(prefix_obj, "scope_type", None) == "dcim.site" and getattr(prefix_obj, "scope_id", None):
        return prefix_obj.scope_id
    site_attr = getattr(prefix_obj, "site", None)
    if site_attr:
        return getattr(site_attr, "id", None)
    scope_attr = getattr(prefix_obj, "scope", None)
    if scope_attr:
        return getattr(scope_attr, "id", None)
    return None


def set_prefix_site_scope(prefix_obj, site_id):
    if get_prefix_site_id(prefix_obj) == site_id:
        return False
    try:
        prefix_obj.scope_type = "dcim.site"
        prefix_obj.scope_id = site_id
        prefix_obj.save()
        return True
    except Exception:
        try:
            prefix_obj.site = site_id
            prefix_obj.save()
            return True
        except Exception:
            return False


# =====================================================================
# 5A. PARSER ROUTEROS (.RSC)
# =====================================================================
def parse_rsc_file(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        raw_lines = f.readlines()

    data = {
        "filepath": filepath,
        "ext": ".rsc",
        "model": "Unknown-RouterOS",
        "serial": "",
        "identity": "UNKNOWN",
        "ethernets": {},
        "eoips": {},
        "bridges": {},
        "bridge_ports": {},
        "all_mentioned_ports": set(),
        "bridge_vlans": [],
        "vlans": {},
        "ips": [],
        "wg_interfaces": set(),
        "vpn_interfaces": set(),
        "wan_interfaces": set(),
        "mgmt_interfaces": set(),
        "lan_interfaces": set(),
        "wg_peers": [],
        "route_gateways": set(),
        "is_router": True,
        "is_vpn_hub": False,
    }

    for line in raw_lines[:25]:
        if line.startswith("# model ="):
            data["model"] = line.split("=", 1)[1].strip()
            if data["model"].upper().startswith(("CRS", "CSS")):
                data["is_router"] = False
        elif line.startswith("# serial number ="):
            data["serial"] = line.split("=", 1)[1].strip()

    logical_lines, buffer = [], ""
    for raw_line in raw_lines:
        line_clean = raw_line.rstrip("\r\n")
        stripped = line_clean.strip()
        if not stripped or stripped.startswith("#"):
            continue
        part = line_clean.lstrip() if buffer else stripped
        if part.endswith("\\"):
            buffer += part[:-1]
        else:
            buffer += part
            logical_lines.append(buffer)
            buffer = ""
    if buffer:
        logical_lines.append(buffer)

    current_section = ""
    for line in logical_lines:
        if line.startswith("/"):
            if "add " not in line and "set " not in line:
                current_section = line
                continue
            else:
                cmd_idx = line.find("add ") if "add " in line else line.find("set ")
                current_section = line[:cmd_idx].strip()
                line = line[cmd_idx:].strip()

        params = {
            k: v.strip('"')
            for k, v in re.findall(r'([a-zA-Z0-9.-]+)=(".*?"|\S+)', line)
        }

        if current_section == "/system identity" and "name" in params:
            data["identity"] = params["name"]

        elif current_section == "/interface ethernet":
            def_match = re.search(r"default-name=([^\s\]]+)", line)
            def_name = def_match.group(1).strip('"') if def_match else params.get("default-name")
            if_name = params.get("name") or def_name
            if if_name and not if_name.startswith("*"):
                data["ethernets"][if_name] = {
                    "name": if_name,
                    "default_name": def_name or if_name,
                    "comment": params.get("comment", ""),
                    "disabled": params.get("disabled") == "yes",
                }

        elif current_section == "/interface eoip" and line.startswith("add"):
            if "name" in params and not params["name"].startswith("*"):
                e_name = params["name"]
                data["eoips"][e_name] = {
                    "name": e_name,
                    "remote": params.get("remote-address", ""),
                    "tunnel_id": params.get("tunnel-id", ""),
                    "comment": params.get("comment", ""),
                    "disabled": params.get("disabled") == "yes",
                }
                if params.get("disabled") != "yes":
                    data["vpn_interfaces"].add(e_name)

        elif current_section == "/interface bridge" and line.startswith("add"):
            if params.get("disabled") != "yes" and "name" in params:
                br_name = params["name"]
                if not br_name.startswith("*"):
                    data["bridges"][br_name] = {
                        "pvid": int(params.get("pvid", 1)),
                        "vlan_filtering": params.get("vlan-filtering") == "yes",
                        "comment": params.get("comment", ""),
                    }

        elif current_section == "/interface bridge port" and line.startswith("add"):
            if "interface" in params and not params["interface"].startswith("*"):
                bp_if = params["interface"]
                data["all_mentioned_ports"].add(bp_if)
                if params.get("disabled") != "yes" and "bridge" in params:
                    data["bridge_ports"][bp_if] = {
                        "bridge": params["bridge"],
                        "pvid": int(params.get("pvid", 1)),
                        "frame_types": params.get("frame-types", "admit-all"),
                        "comment": params.get("comment", ""),
                    }

        elif current_section == "/interface bridge vlan" and line.startswith("add"):
            if params.get("disabled") != "yes" and "vlan-ids" in params:
                vids = expand_vlan_ids(params["vlan-ids"])
                tagged_set = {
                    x.strip() for x in params.get("tagged", "").split(",")
                    if x.strip() and not x.strip().startswith("*")
                }
                untagged_set = {
                    x.strip() for x in params.get("untagged", "").split(",")
                    if x.strip() and not x.strip().startswith("*")
                }
                data["bridge_vlans"].append({
                    "bridge": params.get("bridge", ""),
                    "vids": vids,
                    "tagged": tagged_set,
                    "untagged": untagged_set,
                })

        elif current_section == "/interface vlan" and line.startswith("add"):
            if params.get("disabled") != "yes" and "name" in params and "vlan-id" in params:
                v_if_name = params["name"]
                if not v_if_name.startswith("*"):
                    data["vlans"][v_if_name] = {
                        "vid": int(params["vlan-id"]),
                        "name": v_if_name,
                        "parent": params.get("interface", ""),
                        "comment": params.get("comment", ""),
                    }

        elif current_section == "/interface wireguard" and line.startswith("add"):
            if params.get("disabled") != "yes" and "name" in params:
                data["wg_interfaces"].add(params["name"])
                data["vpn_interfaces"].add(params["name"])

        elif current_section in (
            "/interface ovpn-client", "/interface ovpn-server",
            "/interface sstp-client", "/interface l2tp-client",
            "/interface gre", "/interface ipip"
        ) and line.startswith("add"):
            if params.get("disabled") != "yes" and "name" in params:
                data["vpn_interfaces"].add(params["name"])

        elif current_section == "/interface list member" and line.startswith("add"):
            if params.get("disabled") != "yes" and "interface" in params:
                m_if = params["interface"]
                lst = params.get("list", "").upper()
                if not m_if.startswith("*"):
                    if lst.startswith("WAN"):
                        data["wan_interfaces"].add(m_if)
                    elif "MGMT" in lst:
                        data["mgmt_interfaces"].add(m_if)
                    elif lst in ("LAN", "VLANS"):
                        data["lan_interfaces"].add(m_if)

        elif current_section in ("/ip dhcp-client", "/interface pppoe-client") and line.startswith("add"):
            if params.get("disabled") != "yes" and "interface" in params:
                w_if = params["interface"]
                if not w_if.startswith("*"):
                    data["wan_interfaces"].add(w_if)
                if "name" in params and not params["name"].startswith("*"):
                    data["wan_interfaces"].add(params["name"])

        elif current_section == "/interface wireguard peers" and line.startswith("add"):
            if params.get("disabled") == "yes":
                continue
            if_name = params.get("interface", "")
            endpoint = params.get("endpoint-address", "")
            sn_match = re.match(r"^([a-z0-9]+)\.sn\.mynetname\.net$", endpoint, re.I)
            remote_sn = sn_match.group(1).upper() if sn_match else None

            allowed_str = params.get("allowed-address", "")
            allowed_ips = set()
            for cidr in allowed_str.split(","):
                cidr = cidr.strip()
                if not cidr:
                    continue
                try:
                    ip_obj = ipaddress.ip_interface(cidr)
                    allowed_ips.add(str(ip_obj.ip))
                except ValueError:
                    pass

            data["wg_peers"].append({
                "interface": if_name,
                "name": params.get("name", "") or params.get("comment", ""),
                "allowed_address": allowed_str,
                "allowed_ips": allowed_ips,
                "endpoint": endpoint,
                "remote_sn": remote_sn,
            })

        elif current_section == "/ip route" and line.startswith("add"):
            if params.get("disabled") != "yes" and "gateway" in params:
                for gw in params["gateway"].split(","):
                    data["route_gateways"].add(gw.strip())

        elif current_section == "/ip address" and line.startswith("add"):
            if (
                params.get("disabled") != "yes"
                and "address" in params
                and "interface" in params
                and not params["interface"].startswith("*")
            ):
                data["ips"].append({
                    "address": params["address"],
                    "interface": params["interface"],
                    "comment": params.get("comment", ""),
                })

    if re.search(r"[-_](SW\d*|SWITCH\d*|CORE|POE|CSS\d*|CRS\d*)$", data["identity"], re.I):
        data["is_router"] = False

    for ip_e in data["ips"]:
        if ip_e["interface"] in data["vpn_interfaces"]:
            try:
                ip_if = ipaddress.ip_interface(ip_e["address"])
                if not match_global_mgmt_network(ip_if.ip) and ip_if.ip == ip_if.network.network_address + 1:
                    data["is_vpn_hub"] = True
                    break
            except ValueError:
                pass

    return data


# =====================================================================
# 5B. PARSER SWOS (.SWB - Switche CSS326 / CSS610)
# =====================================================================
def decode_swos_hex_str(hex_str):
    try:
        return (
            bytes.fromhex(hex_str)
            .decode("utf-8", errors="ignore")
            .strip("\x00")
            .strip()
        )
    except Exception:
        return ""


def decode_swos_hex_ip(hex_ip_str):
    val = int(hex_ip_str, 16)
    b_little = val.to_bytes(4, byteorder="little")
    b_big = val.to_bytes(4, byteorder="big")
    if b_little[0] in (10, 172, 192):
        return str(ipaddress.IPv4Address(b_little))
    return str(ipaddress.IPv4Address(b_big))


def parse_swb_file(filepath, default_model="CSS326-24G-2S+"):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    data = {
        "filepath": filepath,
        "ext": ".swb",
        "model": default_model,
        "serial": "",
        "identity": "UNKNOWN-SW",
        "ethernets": {},
        "eoips": {},
        "bridges": {},
        "bridge_ports": {},
        "all_mentioned_ports": set(),
        "bridge_vlans": [],
        "swos_ports": [],
        "vlans": {},
        "ips": [],
        "wg_interfaces": set(),
        "vpn_interfaces": set(),
        "wan_interfaces": set(),
        "mgmt_interfaces": set(),
        "lan_interfaces": set(),
        "wg_peers": [],
        "route_gateways": set(),
        "is_router": False,
        "is_vpn_hub": False,
    }

    sys_match = re.search(r"sys(?:\.b)?:\{([^}]+)\}", content)
    if sys_match:
        sys_block = sys_match.group(1)

        id_match = re.search(r"id:'([0-9a-fA-F]+)'", sys_block)
        if id_match:
            decoded_id = decode_swos_hex_str(id_match.group(1))
            if decoded_id:
                data["identity"] = decoded_id

        ip_match = re.search(r"ip:(0x[0-9a-fA-F]+)", sys_block)
        if ip_match:
            ip_str = decode_swos_hex_ip(ip_match.group(1))
            data["ips"].append({
                "address": f"{ip_str}/24",
                "interface": "mgmt",
                "comment": f"Adres zarządzania ({data['identity']})",
            })

    port_names = []
    port_enabled = []
    link_match = re.search(r"link(?:\.b)?:\{(.*?)\}(?:,[a-zA-Z.]|$)", content, re.DOTALL)
    if link_match:
        link_block = link_match.group(1)
        en_match = re.search(r"en:(0x[0-9a-fA-F]+|\d+)", link_block)
        en_mask = int(en_match.group(1), 16) if (en_match and en_match.group(1).startswith("0x")) else (int(en_match.group(1)) if en_match else 0x03FFFFFF)

        nm_list_match = re.search(r"nm:\[([^\]]+)\]", link_block)
        if nm_list_match:
            raw_hex_names = re.findall(r"'([0-9a-fA-F]*)'", nm_list_match.group(1))
            for idx, h_str in enumerate(raw_hex_names):
                p_name = decode_swos_hex_str(h_str) or (f"Port{idx + 1}" if idx < 24 else f"SFP{idx - 23}")
                port_names.append(p_name)
                port_enabled.append(bool((en_mask >> idx) & 1))

    dvids = []
    vlnis = []
    fwd_match = re.search(r"fwd(?:\.b)?:\{(.*?)\}(?:,[a-zA-Z.]|$)", content, re.DOTALL)
    if fwd_match:
        dvid_match = re.search(r"dvid:\[([^\]]+)\]", fwd_match.group(1))
        if dvid_match:
            dvids = [
                int(x.strip(), 16) if x.strip().startswith("0x") else int(x.strip())
                for x in dvid_match.group(1).split(",") if x.strip()
            ]
        vlni_match = re.search(r"vlni:\[([^\]]+)\]", fwd_match.group(1))
        if vlni_match:
            vlnis = [
                int(x.strip(), 16) if x.strip().startswith("0x") else int(x.strip())
                for x in vlni_match.group(1).split(",") if x.strip()
            ]

    vlan_mbr_map = {}
    vlan_section = re.search(r"vlan(?:\.b)?:\[(.*?)\]", content, re.DOTALL)
    if vlan_section:
        vlan_entries = re.findall(r"\{([^}]+)\}", vlan_section.group(1))
        for entry in vlan_entries:
            vid_match = re.search(r"vid:(0x[0-9a-fA-F]+|\d+)", entry)
            nm_match = re.search(r"nm:'([0-9a-fA-F]*)'", entry)
            mbr_match = re.search(r"mbr:(0x[0-9a-fA-F]+|\d+)", entry)
            if vid_match:
                vid_raw = vid_match.group(1)
                vid = int(vid_raw, 16) if vid_raw.startswith("0x") else int(vid_raw)
                if mbr_match:
                    mbr_raw = mbr_match.group(1)
                    vlan_mbr_map[vid] = int(mbr_raw, 16) if mbr_raw.startswith("0x") else int(mbr_raw)
                if vid == 1:
                    continue
                v_name = (
                    decode_swos_hex_str(nm_match.group(1))
                    if (nm_match and nm_match.group(1))
                    else f"VLAN-{vid}"
                )
                if_key = f"vlan{vid}"
                data["vlans"][if_key] = {"vid": vid, "name": v_name, "parent": "", "comment": ""}

    num_ports = max(len(port_names), len(dvids))
    for idx in range(num_ports):
        p_name = port_names[idx] if idx < len(port_names) else (f"Port{idx + 1}" if idx < 24 else f"SFP{idx - 23}")
        is_en = port_enabled[idx] if idx < len(port_enabled) else True
        dvid = dvids[idx] if idx < len(dvids) else 1
        vlni = vlnis[idx] if idx < len(vlnis) else 0

        member_vids = set()
        for vid, mbr_mask in vlan_mbr_map.items():
            if (mbr_mask >> idx) & 1:
                member_vids.add(vid)

        if vlni == 2 or (member_vids == {dvid} and dvid != 1):
            mode = "access"
            untagged_vid = dvid if dvid != 1 else None
            tagged_vids = set()
        elif member_vids:
            mode = "tagged"
            untagged_vid = dvid if (dvid != 1 and dvid in member_vids) else None
            tagged_vids = {v for v in member_vids if v != untagged_vid and v != 1}
        else:
            mode = None
            untagged_vid = None
            tagged_vids = set()

        if idx < 24:
            def_aliases = [f"Port{idx + 1}", f"ether{idx + 1}", f"ge{idx + 1}"]
        else:
            sfp_num = idx - 23
            def_aliases = [f"SFP{sfp_num}", f"sfp-sfpplus{sfp_num}", f"sfp{sfp_num}", f"sfpplus{sfp_num}"]

        data["swos_ports"].append({
            "index": idx,
            "default_name": def_aliases[0],
            "default_aliases": def_aliases,
            "name": p_name,
            "enabled": is_en,
            "type": "1000base-t" if idx < 24 else "10gbase-x-sfpp",
            "mode": mode,
            "untagged_vid": untagged_vid,
            "tagged_vids": tagged_vids,
        })

    return data


def pre_parse_backup(filepath):
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".swb":
        return parse_swb_file(filepath)
    return parse_rsc_file(filepath)


# =====================================================================
# 6. SYNCHRONIZACJA PORTÓW FIZYCZNYCH, BRIDGE'Y, TUNELI L2 (EOIP) I VLAN-ÓW
# =====================================================================
def infer_default_port_name(if_name):
    low = if_name.lower()
    m_eth = re.match(r"^(ether\d+)[-_].+", low)
    if m_eth:
        return [m_eth.group(1)]
    m_sfp = re.match(r"^sfp(\d+)[-_].+", low)
    if m_sfp:
        num = m_sfp.group(1)
        return [f"sfp-sfpplus{num}", f"sfp{num}", f"sfpplus{num}"]
    if low.startswith("sfp-trunk") or low.startswith("sfp_trunk"):
        return ["sfp-sfpplus1", "sfp1"]
    return []


def update_interface_vlan_assignment(
    nb_iface, mode, untagged_vlan_obj, tagged_vlan_objs,
    parent_id=None, bridge_id=None, label=None, phys_type=None, enabled=None, comment=None, clear_bridge_if_none=False
):
    changed = False

    if phys_type and getattr(nb_iface.type, "value", "") != phys_type:
        nb_iface.type = phys_type
        changed = True

    if enabled is not None and getattr(nb_iface, "enabled", True) != enabled:
        nb_iface.enabled = enabled
        changed = True

    if comment:
        clean_comm = safe_desc(comment)
        curr_d = getattr(nb_iface, "description", "") or ""
        if curr_d != clean_comm and not curr_d.startswith(("VPN <->", "Hub VPN", "Tunel <->")):
            nb_iface.description = clean_comm
            changed = True

    if parent_id and getattr(nb_iface.parent, "id", None) != parent_id:
        nb_iface.parent = parent_id
        changed = True

    current_bridge_id = getattr(getattr(nb_iface, "bridge", None), "id", None)
    if bridge_id and current_bridge_id != bridge_id:
        nb_iface.bridge = bridge_id
        changed = True
    elif clear_bridge_if_none and bridge_id is None and current_bridge_id is not None:
        nb_iface.bridge = None
        changed = True

    if label is not None and getattr(nb_iface, "label", "") != label:
        nb_iface.label = label
        changed = True

    current_mode = getattr(getattr(nb_iface, "mode", None), "value", None)
    current_untagged_id = getattr(getattr(nb_iface, "untagged_vlan", None), "id", None)
    current_tagged_ids = {v.id for v in (getattr(nb_iface, "tagged_vlans", None) or [])}

    target_untagged_id = untagged_vlan_obj.id if untagged_vlan_obj else None
    target_tagged_ids = {v.id for v in tagged_vlan_objs if v}

    if mode:
        if current_mode != mode:
            nb_iface.mode = mode
            changed = True
        if current_untagged_id != target_untagged_id:
            nb_iface.untagged_vlan = target_untagged_id
            changed = True
        if mode == "tagged" and current_tagged_ids != target_tagged_ids:
            nb_iface.tagged_vlans = list(target_tagged_ids)
            changed = True
    elif clear_bridge_if_none and current_mode is not None:
        nb_iface.mode = None
        nb_iface.untagged_vlan = None
        nb_iface.tagged_vlans = []
        changed = True

    if changed:
        try:
            nb_iface.save()
        except Exception as e:
            print(f"      [!] Ostrzeżenie zapisu L2 na porcie {nb_iface.name}: {e}")


def sync_device_l2_ports_and_vlans(device, parsed, vid_to_nb_vlan):
    existing_ifaces = {}
    existing_by_label = {}
    for i in nb.dcim.interfaces.filter(device_id=device.id):
        if i.name.startswith("*"):
            try:
                print(f"[-] Usuwam osierocony wskaźnik interfejsu RouterOS z {device.name}: {i.name}")
                i.delete()
                continue
            except Exception:
                pass
        existing_ifaces[i.name] = i
        lbl = getattr(i, "label", "")
        if lbl:
            existing_by_label[lbl] = i

    if parsed["ext"] == ".swb":
        if "mgmt-swos" in existing_ifaces and "mgmt" not in existing_ifaces:
            old_mgmt = existing_ifaces.pop("mgmt-swos")
            old_mgmt.name = "mgmt"
            old_mgmt.save()
            existing_ifaces["mgmt"] = old_mgmt
        elif "mgmt-swos" in existing_ifaces and "mgmt" in existing_ifaces:
            try:
                existing_ifaces.pop("mgmt-swos").delete()
            except Exception:
                pass

        for sp in parsed.get("swos_ports", []):
            p_name = sp["name"]
            def_name = sp["default_name"]
            aliases = sp.get("default_aliases", [def_name])

            nb_if = existing_ifaces.get(p_name)
            if not nb_if and def_name in existing_by_label:
                nb_if = existing_by_label[def_name]
                existing_ifaces.pop(nb_if.name, None)
                nb_if.name = p_name
                nb_if.save()
                existing_ifaces[p_name] = nb_if

            for al in aliases:
                if al != p_name and al in existing_ifaces:
                    cand_dup = existing_ifaces[al]
                    if not nb_if:
                        nb_if = existing_ifaces.pop(al)
                        nb_if.name = p_name
                        nb_if.label = def_name if p_name != def_name else ""
                        nb_if.save()
                        existing_ifaces[p_name] = nb_if
                    elif not getattr(cand_dup, "cable", None) and getattr(cand_dup, "count_ipaddresses", 0) == 0:
                        try:
                            print(f"[-] Usuwam nadmiarowy port z szablonu na {device.name}: {al} (zastąpiony przez {p_name})")
                            existing_ifaces.pop(al).delete()
                        except Exception:
                            pass

            if not nb_if:
                nb_if = nb.dcim.interfaces.create(
                    device=device.id,
                    name=p_name,
                    label=def_name if p_name != def_name else "",
                    type=sp["type"],
                    enabled=sp.get("enabled", True),
                )
                existing_ifaces[p_name] = nb_if

            untagged_obj = vid_to_nb_vlan.get(sp["untagged_vid"]) if sp["untagged_vid"] else None
            tagged_objs = [vid_to_nb_vlan[v] for v in sp["tagged_vids"] if v in vid_to_nb_vlan]
            update_interface_vlan_assignment(
                nb_if,
                mode=sp["mode"],
                untagged_vlan_obj=untagged_obj,
                tagged_vlan_objs=tagged_objs,
                label=def_name if p_name != def_name else "",
                phys_type=sp["type"],
                enabled=sp.get("enabled", True),
            )
        return existing_ifaces

    bridge_ifaces = {}
    for br_name, br_info in parsed.get("bridges", {}).items():
        nb_br = existing_ifaces.get(br_name)
        if not nb_br:
            nb_br = nb.dcim.interfaces.create(
                device=device.id,
                name=br_name,
                type="bridge",
                description=safe_desc(br_info.get("comment", "")),
            )
            existing_ifaces[br_name] = nb_br
        elif getattr(nb_br.type, "value", "") != "bridge":
            nb_br.type = "bridge"
            nb_br.save()
        bridge_ifaces[br_name] = nb_br

    for eoip_name, eoip_info in parsed.get("eoips", {}).items():
        tid = eoip_info.get("tunnel_id", "")
        rem = eoip_info.get("remote", "")
        tid_str = f" (ID: {tid})" if tid else ""
        rem_str = f" <-> {rem}" if rem else ""
        eoip_desc = safe_desc(eoip_info.get("comment") or f"Tunel EoIP{tid_str}{rem_str}")
        is_en = not eoip_info.get("disabled", False)

        nb_eoip = existing_ifaces.get(eoip_name)
        if not nb_eoip:
            nb_eoip = nb.dcim.interfaces.create(
                device=device.id,
                name=eoip_name,
                type="virtual",
                enabled=is_en,
                description=eoip_desc,
            )
            existing_ifaces[eoip_name] = nb_eoip
        else:
            update_interface_vlan_assignment(
                nb_eoip,
                mode=None,
                untagged_vlan_obj=None,
                tagged_vlan_objs=[],
                phys_type="virtual",
                enabled=is_en,
                comment=eoip_desc,
            )

    all_phys_names = (
        set(parsed.get("ethernets", {}).keys())
        | set(parsed.get("bridge_ports", {}).keys())
        | set(parsed.get("all_mentioned_ports", set()))
    )
    for if_name in sorted(all_phys_names):
        if (
            if_name.startswith("*")
            or if_name in bridge_ifaces
            or if_name in parsed.get("vlans", {})
            or if_name in parsed.get("eoips", {})
            or if_name in parsed.get("vpn_interfaces", set())
        ):
            continue

        eth_info = parsed.get("ethernets", {}).get(if_name, {})
        def_name = eth_info.get("default_name", if_name)
        possible_def_names = [def_name] if def_name != if_name else []
        for inf_def in infer_default_port_name(if_name):
            if inf_def not in possible_def_names:
                possible_def_names.append(inf_def)

        if_type = "10gbase-x-sfpp" if "sfp" in if_name.lower() else "1000base-t"
        is_enabled = not eth_info.get("disabled", False)
        comment = safe_desc(eth_info.get("comment", ""))
        label_val = possible_def_names[0] if possible_def_names else ""

        nb_if = existing_ifaces.get(if_name)

        # Jeśli port był wcześniej przemianowany (np. ether1_WAN -> ether1-wan1 lub sfp1_TRUNK -> sfp-trunk-sw-core),
        # znajdź go po jego etykiecie sprzętowej (label='ether1' / 'sfp-sfpplus1') i przemianuj w miejscu!
        if not nb_if and label_val and label_val in existing_by_label:
            cand_by_lbl = existing_by_label[label_val]
            if cand_by_lbl.name not in all_phys_names:
                old_n = cand_by_lbl.name
                existing_ifaces.pop(old_n, None)
                cand_by_lbl.name = if_name
                cand_by_lbl.type = if_type
                cand_by_lbl.enabled = is_enabled
                if comment:
                    cand_by_lbl.description = comment
                cand_by_lbl.save()
                nb_if = cand_by_lbl
                existing_ifaces[if_name] = nb_if
                print(f"[~] Zmieniono nazwę portu fizycznego na {device.name}: {old_n} -> {if_name}")

        for cand_def in possible_def_names:
            if cand_def in existing_ifaces and cand_def != if_name:
                raw_tmpl_if = existing_ifaces[cand_def]
                if not nb_if:
                    nb_if = existing_ifaces.pop(cand_def)
                    nb_if.name = if_name
                    nb_if.label = label_val
                    nb_if.type = if_type
                    nb_if.enabled = is_enabled
                    if comment:
                        nb_if.description = comment
                    nb_if.save()
                    existing_ifaces[if_name] = nb_if
                else:
                    if not getattr(raw_tmpl_if, "cable", None) and getattr(raw_tmpl_if, "count_ipaddresses", 0) == 0:
                        try:
                            print(f"[-] Usuwam duplikat portu z szablonu na {device.name}: {cand_def} (aktywny port: {if_name})")
                            existing_ifaces.pop(cand_def).delete()
                        except Exception:
                            pass

        if not nb_if:
            nb_if = nb.dcim.interfaces.create(
                device=device.id,
                name=if_name,
                label=label_val,
                type=if_type,
                enabled=is_enabled,
                description=comment,
            )
            existing_ifaces[if_name] = nb_if
        else:
            update_interface_vlan_assignment(
                nb_if,
                mode=None,
                untagged_vlan_obj=None,
                tagged_vlan_objs=[],
                label=label_val if label_val else None,
                phys_type=if_type,
                enabled=is_enabled,
                comment=comment if comment else None,
            )

    port_untagged = {}
    port_tagged = {}

    for bp_if, bp_info in parsed.get("bridge_ports", {}).items():
        if bp_info["pvid"] and bp_info["pvid"] != 1:
            port_untagged[bp_if] = bp_info["pvid"]

    for bv in parsed.get("bridge_vlans", []):
        for vid in bv["vids"]:
            if vid == 1:
                continue
            for t_if in bv["tagged"]:
                port_tagged.setdefault(t_if, set()).add(vid)
            for u_if in bv["untagged"]:
                port_untagged[u_if] = vid

    if not parsed.get("bridge_vlans") and parsed.get("vlans"):
        has_vid_10 = 10 in vid_to_nb_vlan
        for bp_if, bp_info in parsed.get("bridge_ports", {}).items():
            if bp_if not in port_untagged and has_vid_10:
                port_untagged[bp_if] = 10

    all_touched_ports = (
        set(parsed.get("bridge_ports", {}).keys())
        | set(port_untagged.keys())
        | set(port_tagged.keys())
        | set(parsed.get("all_mentioned_ports", set()))
    )
    for p_name in all_touched_ports:
        nb_if = existing_ifaces.get(p_name)
        if not nb_if:
            continue

        bp_info = parsed.get("bridge_ports", {}).get(p_name, {})
        br_obj = bridge_ifaces.get(bp_info.get("bridge", ""))
        br_id = br_obj.id if br_obj and p_name != br_obj.name else None

        u_vid = port_untagged.get(p_name) if (bp_info or p_name in bridge_ifaces) else None
        t_vids = (port_tagged.get(p_name, set()) - ({u_vid} if u_vid else set())) if (bp_info or p_name in bridge_ifaces) else set()

        if t_vids:
            mode = "tagged"
        elif u_vid:
            mode = "access"
        else:
            mode = None

        u_vlan_obj = vid_to_nb_vlan.get(u_vid) if u_vid else None
        t_vlan_objs = [vid_to_nb_vlan[v] for v in t_vids if v in vid_to_nb_vlan]

        update_interface_vlan_assignment(
            nb_if,
            mode=mode,
            untagged_vlan_obj=u_vlan_obj,
            tagged_vlan_objs=t_vlan_objs,
            bridge_id=br_id,
            clear_bridge_if_none=(p_name not in bridge_ifaces),
        )

    return existing_ifaces


# =====================================================================
# 7. FIZYCZNE ŁĄCZENIE URZĄDZEŃ W ODDZIALE KABLAMI (ROUTER <-> CORE <-> SWITCH)
# =====================================================================
def match_target_device_from_port_text(port_text, my_device, site_devices):
    txt = port_text.upper()

    for cand in site_devices:
        if cand.name.upper() in txt:
            return cand

    sw_matches = re.findall(r"(?:^|[-_\s(])(?:SW|SWITCH)[-_]?(\d+)(?:$|[-_\s)])", txt)
    if sw_matches:
        target_num = sw_matches[-1]
        for cand in site_devices:
            cand_up = cand.name.upper()
            if re.search(rf"(?:^|[-_])(?:SW|SWITCH)[-_]?0*{target_num}(?:$|[-_])", cand_up):
                return cand

    if re.search(r"(?:^|[-_\s(])CORE(?:$|[-_\s)])", txt):
        for cand in site_devices:
            if "CORE" in cand.name.upper() or getattr(getattr(cand, "role", None), "name", "") == "Core Switch":
                return cand

    if re.search(r"(?:^|[-_\s(])(?:R\d*|RTR\d*|ROUTER)(?:$|[-_\s)])", txt):
        for cand in site_devices:
            if getattr(getattr(cand, "role", None), "name", "") == "Router":
                return cand

    return None


def find_reciprocal_port_on_target(my_device, my_if, target_dev, all_site_devices):
    target_ifaces = [
        i for i in nb.dcim.interfaces.filter(device_id=target_dev.id)
        if getattr(i.type, "value", "") not in ("virtual", "bridge")
    ]

    for tif in target_ifaces:
        t_txt = f"{tif.name} {getattr(tif, 'description', '')}"
        matched_back = match_target_device_from_port_text(t_txt, target_dev, all_site_devices)
        if matched_back and matched_back.id == my_device.id:
            return tif

    generic_trunk_candidates = []
    for tif in target_ifaces:
        if getattr(tif, "cable", None):
            continue
        t_txt = f"{tif.name} {getattr(tif, 'description', '')}"
        if "TRUNK" in t_txt.upper():
            other_match = match_target_device_from_port_text(t_txt, target_dev, all_site_devices)
            if not other_match or other_match.id == my_device.id:
                generic_trunk_candidates.append(tif)

    if len(generic_trunk_candidates) == 1:
        return generic_trunk_candidates[0]

    return None


def create_netbox_cable_if_needed(dev_a, if_a, dev_b, if_b):
    if_a_fresh = nb.dcim.interfaces.get(if_a.id)
    if_b_fresh = nb.dcim.interfaces.get(if_b.id)

    if getattr(if_a_fresh, "cable", None) or getattr(if_b_fresh, "cable", None):
        return

    try:
        nb.dcim.cables.create(
            a_terminations=[{"object_type": "dcim.interface", "object_id": if_a.id}],
            b_terminations=[{"object_type": "dcim.interface", "object_id": if_b.id}],
            status="connected",
            label=safe_desc(f"{short_dev_label(dev_a.name)} <-> {short_dev_label(dev_b.name)}", 100),
        )
        print(f"[===] Połączono kablem w NetBoxie: {dev_a.name} ({if_a.name}) <===> {dev_b.name} ({if_b.name})")
    except Exception:
        try:
            nb.dcim.cables.create(
                termination_a_type="dcim.interface",
                termination_a_id=if_a.id,
                termination_b_type="dcim.interface",
                termination_b_id=if_b.id,
                status="connected",
            )
            print(f"[===] Połączono kablem w NetBoxie: {dev_a.name} ({if_a.name}) <===> {dev_b.name} ({if_b.name})")
        except Exception as e:
            print(f"      [!] Nie udało się utworzyć kabla {dev_a.name} ({if_a.name}) <-> {dev_b.name} ({if_b.name}): {e}")


def link_site_l2_devices(device, site, existing_ifaces):
    all_site_devices = list(nb.dcim.devices.filter(site_id=site.id))
    other_site_devices = [d for d in all_site_devices if d.id != device.id]
    if not other_site_devices:
        return

    for if_name, nb_if in existing_ifaces.items():
        if getattr(nb_if.type, "value", "") in ("virtual", "bridge"):
            continue

        search_txt = f"{if_name} {getattr(nb_if, 'description', '')}"
        target_dev = match_target_device_from_port_text(search_txt, device, other_site_devices)
        if not target_dev:
            continue

        current_desc = getattr(nb_if, "description", "") or ""
        if not current_desc or current_desc.startswith("Połączenie L2"):
            new_l2_desc = safe_desc(f"Trunk <-> {short_dev_label(target_dev.name)}")
            if current_desc != new_l2_desc:
                nb_if.description = new_l2_desc
                nb_if.save()

        remote_port = find_reciprocal_port_on_target(device, nb_if, target_dev, all_site_devices)
        if remote_port:
            create_netbox_cable_if_needed(device, nb_if, target_dev, remote_port)


# =====================================================================
# 8. INTELIGENTNE WIĄZANIE ROUTERÓW TUNELAMI VPN I ZWIĘZŁE OPISY
# =====================================================================
def are_routers_peered(parsed, if_name, ip_iface, other_dev, other_ip_clean):
    if ip_iface.network.prefixlen >= 30:
        return True

    if_peers = [p for p in parsed.get("wg_peers", []) if p["interface"] == if_name]
    other_serial = (getattr(other_dev, "serial", "") or "").upper()
    other_name_upper = other_dev.name.upper()
    other_short = other_name_upper.split("_", 1)[-1]
    other_short = re.sub(r"[-_](R\d*|RTR\d*|ROUTER\d*)$", "", other_short, flags=re.I)

    for p in if_peers:
        if other_ip_clean in p.get("allowed_ips", set()):
            return True
        if p.get("remote_sn") and other_serial and p["remote_sn"] == other_serial:
            return True
        peer_name_clean = p.get("name", "").upper().strip()
        if peer_name_clean and len(peer_name_clean) >= 3:
            if peer_name_clean in other_name_upper or (other_short and other_short in peer_name_clean):
                return True

    if other_ip_clean in parsed.get("route_gateways", set()):
        return True

    return False


def get_available_termination_interface(dev_obj, base_iface_obj, peer_dev_obj, peer_ip_str, tunnel_id, is_hub_endpoint=False, active_sub_ifaces=None):
    sub_if_name = f"{base_iface_obj.name} -> {peer_dev_obj.name}"
    sub_iface = safe_first(nb.dcim.interfaces, device_id=dev_obj.id, name=sub_if_name)
    short_peer = short_dev_label(peer_dev_obj.name)
    expected_sub_desc = safe_desc(f"Tunel <-> {short_peer} ({peer_ip_str})")

    # Sprawdź wszystkie istniejące zakończenia tego tunelu na tym urządzeniu (np. na dawnym wireguard1 -> ...)
    dev_iface_ids = {i.id for i in nb.dcim.interfaces.filter(device_id=dev_obj.id)}
    existing_terms_for_tunnel = [
        t for t in nb.vpn.tunnel_terminations.filter(tunnel_id=tunnel_id)
        if getattr(t, "termination_id", None) in dev_iface_ids
    ]

    if is_hub_endpoint:
        if not sub_iface:
            sub_iface = nb.dcim.interfaces.create(
                device=dev_obj.id,
                name=sub_if_name,
                type="virtual",
                parent=base_iface_obj.id,
                description=expected_sub_desc,
            )
        else:
            changed = False
            if getattr(sub_iface, "description", "") != expected_sub_desc:
                sub_iface.description = expected_sub_desc
                changed = True
            if getattr(getattr(sub_iface, "parent", None), "id", None) != base_iface_obj.id:
                sub_iface.parent = base_iface_obj.id
                changed = True
            if changed:
                sub_iface.save()

        if active_sub_ifaces is not None:
            active_sub_ifaces.add(sub_iface.name)

        for old_term in existing_terms_for_tunnel:
            if old_term.termination_id != sub_iface.id:
                try:
                    old_term.termination_id = sub_iface.id
                    old_term.save()
                    print(f"      [~] Przeniesiono zakończenie tunelu na: {dev_obj.name} ({sub_if_name})")
                except Exception:
                    try:
                        old_term.delete()
                    except Exception:
                        pass
        return sub_iface

    existing_on_base = safe_first(nb.vpn.tunnel_terminations, termination_id=base_iface_obj.id)
    if existing_on_base and getattr(existing_on_base.tunnel, "id", None) == tunnel_id:
        return base_iface_obj

    if sub_iface:
        existing_on_sub = safe_first(nb.vpn.tunnel_terminations, termination_id=sub_iface.id)
        if existing_on_sub and getattr(existing_on_sub.tunnel, "id", None) == tunnel_id:
            if getattr(sub_iface, "description", "") != expected_sub_desc:
                sub_iface.description = expected_sub_desc
                sub_iface.save()
            if active_sub_ifaces is not None:
                active_sub_ifaces.add(sub_iface.name)
            return sub_iface

    if not existing_on_base:
        return base_iface_obj

    if not sub_iface:
        sub_iface = nb.dcim.interfaces.create(
            device=dev_obj.id,
            name=sub_if_name,
            type="virtual",
            parent=base_iface_obj.id,
            description=expected_sub_desc,
        )
    elif getattr(sub_iface, "description", "") != expected_sub_desc:
        sub_iface.description = expected_sub_desc
        sub_iface.save()
    if active_sub_ifaces is not None:
        active_sub_ifaces.add(sub_iface.name)
    return sub_iface


def ensure_netbox_vpn_tunnel(tenant, dev_a, iface_a, ip_a, dev_b, iface_b, ip_b, network_str, active_sub_ifaces=None):
    try:
        net_obj = ipaddress.ip_network(network_str, strict=False)
        hub_ip_str = str(net_obj.network_address + 1) if net_obj.prefixlen < 30 else None

        pair = sorted([(dev_a, iface_a, ip_a), (dev_b, iface_b, ip_b)], key=lambda x: x[0].name)
        d1, if1, ip1 = pair[0]
        d2, if2, ip2 = pair[1]
        tunnel_name = f"{d1.name} <-> {d2.name} ({network_str})"

        t_group = find_by_name_or_slug(
            nb.vpn.tunnel_groups, name="Site-to-Site WireGuard", slug="site-to-site-wireguard"
        )
        if not t_group:
            t_group = nb.vpn.tunnel_groups.create(
                name="Site-to-Site WireGuard", slug="site-to-site-wireguard"
            )

        tunnel = safe_first(nb.vpn.tunnels, name=tunnel_name)
        # Jeśli jedno z urządzeń zmieniło nazwę (np. CLIENT-A_SITE-01-R -> CLIENT-A_SITE-01-R01),
        # znajdź istniejący tunel po znormalizowanych nazwach i zaktualizuj jego nazwę!
        if not tunnel:
            norm_d1 = normalize_device_base_identity(d1.name)
            norm_d2 = normalize_device_base_identity(d2.name)
            for cand_t in nb.vpn.tunnels.filter(tenant_id=tenant.id):
                if f"({network_str})" in cand_t.name and " <-> " in cand_t.name:
                    parts_t = cand_t.name.split(f" ({network_str})")[0].split(" <-> ")
                    if len(parts_t) == 2:
                        if {normalize_device_base_identity(parts_t[0]), normalize_device_base_identity(parts_t[1])} == {norm_d1, norm_d2}:
                            tunnel = cand_t
                            print(f"[~] Aktualizuję nazwę tunelu VPN: {cand_t.name} -> {tunnel_name}")
                            tunnel.name = tunnel_name
                            tunnel.save()
                            break

        expected_desc = safe_desc(f"{short_dev_label(d1.name)} ({ip1}) <-> {short_dev_label(d2.name)} ({ip2})")
        if not tunnel:
            print(f"[<->] Tworzę powiązanie VPN Tunnel: {tunnel_name}")
            tunnel = nb.vpn.tunnels.create(
                name=tunnel_name,
                status="active",
                group=t_group.id,
                encapsulation="wireguard",
                tenant=tenant.id,
                description=expected_desc,
            )
        elif getattr(tunnel, "description", "") != expected_desc:
            tunnel.description = expected_desc
            tunnel.save()

        endpoints = [
            (d1, if1, ip1, d2, ip2),
            (d2, if2, ip2, d1, ip1),
        ]
        for dev_obj, base_iface_obj, my_ip_str, peer_dev_obj, peer_ip_str in endpoints:
            try:
                is_hub_end = (hub_ip_str is not None and my_ip_str == hub_ip_str)
                term_role = "hub" if is_hub_end else ("spoke" if hub_ip_str is not None else "peer")

                target_iface = get_available_termination_interface(
                    dev_obj, base_iface_obj, peer_dev_obj, peer_ip_str, tunnel.id,
                    is_hub_endpoint=is_hub_end,
                    active_sub_ifaces=(active_sub_ifaces if dev_obj.id == dev_a.id else None),
                )
                term = safe_first(
                    nb.vpn.tunnel_terminations,
                    tunnel_id=tunnel.id,
                    termination_id=target_iface.id,
                )
                if not term:
                    try:
                        nb.vpn.tunnel_terminations.create(
                            tunnel=tunnel.id,
                            role=term_role,
                            termination_type="dcim.interface",
                            termination_id=target_iface.id,
                        )
                    except Exception:
                        nb.vpn.tunnel_terminations.create(
                            tunnel=tunnel.id,
                            role="peer",
                            termination_type="dcim.interface",
                            termination_id=target_iface.id,
                        )
                    print(f"      [+] Podpięto zakończenie tunelu ({term_role.upper()}): {dev_obj.name} ({target_iface.name})")
            except Exception as term_err:
                print(f"      [!] Ostrzeżenie Termination dla {dev_obj.name}: {term_err}")
    except Exception as e:
        print(f"[!] Błąd synchronizacji obiektu VPN Tunnel: {e}")


def remove_bogus_vpn_tunnel(dev_a, dev_b, network_str):
    try:
        names = sorted([dev_a.name, dev_b.name])
        tunnel_name = f"{names[0]} <-> {names[1]} ({network_str})"
        bogus_tunnel = safe_first(nb.vpn.tunnels, name=tunnel_name)
        if bogus_tunnel:
            print(f"[-] Usuwam nieprawidłowy tunel pomiędzy oddziałami Spoke: {tunnel_name}")
            bogus_tunnel.delete()
    except Exception:
        pass


def format_vpn_interface_description(is_hub, rw_count, peered_tuples):
    short_names = sorted({short_dev_label(dev_name) for dev_name, _ in peered_tuples})
    rw_suffix = f" (+{rw_count} zdalnych)" if rw_count > 0 else ""

    if is_hub or len(peered_tuples) > 1:
        if short_names:
            return safe_desc(f"Hub VPN -> {', '.join(short_names)}{rw_suffix}")
        return safe_desc(f"Hub VPN{rw_suffix}")

    if len(peered_tuples) == 1:
        peer_dev_name, peer_ip = peered_tuples[0]
        return safe_desc(f"VPN <-> {short_dev_label(peer_dev_name)} ({peer_ip}){rw_suffix}")

    if rw_count > 0:
        return safe_desc(f"VPN Zdalny dostęp ({rw_count} peerów)")

    return ""


def refresh_remote_vpn_interface_description(remote_iface, remote_ip_clean, all_vrf_ips, network_str):
    net_obj = ipaddress.ip_network(network_str, strict=False)
    is_remote_hub = (net_obj.prefixlen < 30 and remote_ip_clean == str(net_obj.network_address + 1))

    curr_desc = getattr(remote_iface, "description", "") or ""
    rw_match = re.search(r"(?:Zdalny dostęp:\s*(\d+)|\(\+(\d+)\s*zdalnych\))", curr_desc)
    rw_count = int(rw_match.group(1) or rw_match.group(2)) if rw_match else 0

    remote_peers = []
    if is_remote_hub:
        for ip_obj in all_vrf_ips:
            if_id = getattr(ip_obj, "assigned_object_id", None)
            if not if_id or if_id == remote_iface.id:
                continue
            other_if = nb.dcim.interfaces.get(if_id)
            if other_if and getattr(other_if, "device", None):
                ip_c = str(ipaddress.ip_interface(ip_obj.address).ip)
                remote_peers.append((other_if.device.name, ip_c))
    else:
        for ip_obj in all_vrf_ips:
            if_id = getattr(ip_obj, "assigned_object_id", None)
            if not if_id or if_id == remote_iface.id:
                continue
            ip_c = str(ipaddress.ip_interface(ip_obj.address).ip)
            if net_obj.prefixlen >= 30 or ip_c == str(net_obj.network_address + 1):
                other_if = nb.dcim.interfaces.get(if_id)
                if other_if and getattr(other_if, "device", None):
                    remote_peers.append((other_if.device.name, ip_c))

    new_desc = format_vpn_interface_description(is_remote_hub, rw_count, remote_peers)
    if new_desc and new_desc != curr_desc:
        remote_iface.description = new_desc
        remote_iface.save()


def update_vpn_prefix_summary_description(nb_prefix, all_vrf_ips, network_str):
    if not nb_prefix:
        return

    net_obj = ipaddress.ip_network(network_str, strict=False)
    hub_ip_str = str(net_obj.network_address + 1) if net_obj.prefixlen < 30 else None

    hub_short = None
    spoke_shorts = set()

    for ip_obj in all_vrf_ips:
        iface_id = getattr(ip_obj, "assigned_object_id", None)
        if not iface_id:
            continue
        iface = nb.dcim.interfaces.get(iface_id)
        if not iface or not getattr(iface, "device", None):
            continue
        short_name = short_dev_label(iface.device.name)
        ip_clean = str(ipaddress.ip_interface(ip_obj.address).ip)
        if hub_ip_str and ip_clean == hub_ip_str:
            hub_short = short_name
        else:
            spoke_shorts.add(short_name)

    sorted_spokes = sorted(spoke_shorts)
    if net_obj.prefixlen >= 30 and len(sorted_spokes) >= 2:
        new_pfx_desc = safe_desc(f"Tunel P2P: {' <-> '.join(sorted_spokes)}")
    elif hub_short and sorted_spokes:
        new_pfx_desc = safe_desc(f"Pula VPN (Hub: {hub_short} | Oddziały: {', '.join(sorted_spokes)})")
    elif hub_short:
        new_pfx_desc = safe_desc(f"Pula VPN (Hub: {hub_short})")
    elif len(sorted_spokes) >= 2:
        new_pfx_desc = safe_desc(f"Tunel VPN: {' <-> '.join(sorted_spokes)}")
    else:
        return

    if getattr(nb_prefix, "description", "") != new_pfx_desc:
        nb_prefix.description = new_pfx_desc
        nb_prefix.save()


def link_router_tunnels(device, vrf, tenant, parsed, vpn_interfaces_map):
    active_sub_ifaces = set()
    for if_name, info in vpn_interfaces_map.items():
        nb_iface = info["nb_iface"]
        ip_iface = info["ip_iface"]
        network_str = str(ip_iface.network)
        nb_prefix = info["nb_prefix"]
        my_ip_clean = str(ip_iface.ip)

        is_hub_here = (ip_iface.network.prefixlen < 30 and ip_iface.ip == ip_iface.network.network_address + 1)
        rw_count = count_roadwarrior_peers(if_name, parsed)

        all_vrf_ips = list(nb.ipam.ip_addresses.filter(parent=network_str, vrf_id=vrf.id))
        peered_tuples = []

        for other_ip in all_vrf_ips:
            other_iface_id = getattr(other_ip, "assigned_object_id", None)
            if not other_iface_id or other_iface_id == nb_iface.id:
                continue

            other_ip_clean = str(ipaddress.ip_interface(other_ip.address).ip)
            if other_ip_clean == my_ip_clean:
                continue

            other_iface = nb.dcim.interfaces.get(other_iface_id)
            if not other_iface or getattr(other_iface.device, "id", None) == device.id:
                continue

            other_dev = nb.dcim.devices.get(other_iface.device.id)
            if not other_dev:
                continue

            if not are_routers_peered(parsed, if_name, ip_iface, other_dev, other_ip_clean):
                remove_bogus_vpn_tunnel(device, other_dev, network_str)
                continue

            print(
                f"[<->] Powiązano tunel VPN: {device.name} ({if_name}: {my_ip_clean}) "
                f"<-> {other_dev.name} ({other_iface.name}: {other_ip_clean})"
            )
            peered_tuples.append((other_dev.name, other_ip_clean))
            ensure_netbox_vpn_tunnel(
                tenant, device, nb_iface, my_ip_clean, other_dev, other_iface, other_ip_clean,
                network_str, active_sub_ifaces=active_sub_ifaces
            )
            refresh_remote_vpn_interface_description(
                other_iface, other_ip_clean, all_vrf_ips, network_str
            )

        new_my_desc = format_vpn_interface_description(is_hub_here, rw_count, peered_tuples)
        if new_my_desc and getattr(nb_iface, "description", "") != new_my_desc:
            nb_iface.description = new_my_desc
            nb_iface.save()

        update_vpn_prefix_summary_description(nb_prefix, all_vrf_ips, network_str)

    return active_sub_ifaces


# =====================================================================
# 9. GŁÓWNA FUNKCJA SYNCHRONIZUJĄCA (.RSC oraz .SWB)
# =====================================================================
def find_existing_device_for_only_new(serial, device_name):
    """Wyszukuje istniejące urządzenie w NetBoxie: priorytetowo po SN, a w drugiej kolejności po nazwie."""
    if serial:
        dev_by_sn = safe_first(nb.dcim.devices, serial=serial)
        if dev_by_sn:
            return dev_by_sn, "serial"
    if device_name:
        dev_by_name = safe_first(nb.dcim.devices, name=device_name)
        if dev_by_name:
            return dev_by_name, "name"
    return None, None


def import_parsed_to_netbox(parsed, force_tenant=None, force_site=None, only_new=False):
    filepath = parsed["filepath"]
    ext = parsed["ext"]
    identity = parsed["identity"]
    is_router = parsed["is_router"]

    source_for_naming = identity
    if "_" not in identity:
        filename_base = os.path.splitext(os.path.basename(filepath))[0]
        if "_" in filename_base:
            source_for_naming = filename_base.upper()
            if identity in ("UNKNOWN-SW", "UNKNOWN", "MikroTik", "SwOS"):
                identity = source_for_naming

    if only_new:
        existing_dev, matched_by = find_existing_device_for_only_new(
            parsed.get("serial", ""), identity
        )
        if existing_dev:
            status_obj = getattr(existing_dev, "status", None)
            status_val = getattr(status_obj, "value", str(status_obj or ""))
            if str(status_val).lower() == "active":
                match_info = (
                    f"SN: {parsed.get('serial')}"
                    if matched_by == "serial"
                    else f"nazwa: {identity}"
                )
                print(
                    f"[=] Pomijam (--only-new): urządzenie '{existing_dev.name}' już istnieje w NetBoxie "
                    f"ze statusem 'active' (dopasowanie po {match_info}). Source of Truth nienaruszony."
                )
                return False

    if force_tenant and force_site:
        tenant_name, site_name = force_tenant, force_site
    else:
        parts = source_for_naming.split("_", 1)
        tenant_name = parts[0].upper()
        rest_of_name = parts[1] if len(parts) > 1 else ""

        site_name = None
        existing_tenant = find_by_name_or_slug(
            nb.tenancy.tenants, name=tenant_name, slug=make_slug(tenant_name)
        )

        candidate_site = re.sub(
            r"([-_](R\d*|RTR\d*|ROUTER\d*|SW\d*|SWITCH\d*|CORE|POE|CSS\d*|CRS\d*|FR))+\b",
            "",
            rest_of_name,
            flags=re.I,
        ).strip("-_").replace("_", " ").replace(".", " ")

        if existing_tenant and candidate_site:
            client_sites = list(
                nb.dcim.sites.filter(tenant_id=existing_tenant.id)
            ) + list(nb.dcim.sites.filter(q=tenant_name))

            for s in client_sites:
                clean_s = s.name.replace(tenant_name, "").strip(" -_.").replace("_", " ").replace(".", " ").upper()
                if clean_s == candidate_site.upper():
                    site_name = s.name
                    break

        if not site_name:
            site_name = candidate_site.title() if candidate_site else "Glowna"

    dev_role_name = okresl_role_urzadzenia(parsed["model"], identity, parsed["ips"], is_router)

    print(
        f"\n=== [{dev_role_name.upper()}] Synchronizuję ({ext.upper()}): {identity} "
        f"(Plik: {os.path.basename(filepath)}) -> Klient: {tenant_name}, Oddział: {site_name} ==="
    )

    tenant = get_or_create_tenant(tenant_name)
    vrf = get_or_create_vrf(tenant)
    site = get_or_create_site(tenant, site_name)
    vlan_group = get_or_create_vlan_group(site, tenant)
    device = get_or_create_device(
        identity, parsed["model"], parsed["serial"], site, tenant, dev_role_name, parsed=parsed
    )

    # 1. Synchronizacja VLAN-ów
    netbox_vlans = {}
    vid_to_nb_vlan = {}

    all_file_vids = {}
    for if_name, v_info in parsed["vlans"].items():
        all_file_vids[v_info["vid"]] = (if_name, v_info["name"], v_info["comment"])

    for bv in parsed.get("bridge_vlans", []):
        for vid in bv["vids"]:
            if vid != 1 and vid not in all_file_vids:
                all_file_vids[vid] = (f"vlan{vid}", f"VLAN-{vid}", "")

    for bp_if, bp_info in parsed.get("bridge_ports", {}).items():
        vid = bp_info.get("pvid", 1)
        if vid != 1 and vid not in all_file_vids:
            all_file_vids[vid] = (f"vlan{vid}", f"VLAN-{vid}", "")

    existing_group_vlans = list(nb.ipam.vlans.filter(group_id=vlan_group.id))
    by_vid = {v.vid: v for v in existing_group_vlans}
    by_name_lower = {v.name.lower(): v for v in existing_group_vlans}

    for vid, (if_name, raw_v_name, v_comment) in sorted(all_file_vids.items()):
        role_name = zgadnij_role_podsieci(
            vid=vid, network_str="", if_name=raw_v_name, comment=v_comment, parsed=parsed
        )
        role_obj = get_or_create_role(role_name)
        clean_vlan_name = (
            re.sub(r"^vlan\d+[-_]?", "", raw_v_name, flags=re.I).strip()
            or f"VLAN-{vid}"
        )

        conflict_vlan = by_name_lower.get(clean_vlan_name.lower())
        if conflict_vlan and conflict_vlan.vid != vid:
            clean_vlan_name = f"{clean_vlan_name} ({vid})"

        nb_vlan = by_vid.get(vid)
        if not nb_vlan:
            print(f"[+] Tworzę VLAN {vid} ({clean_vlan_name}) w {site.name}")
            nb_vlan = nb.ipam.vlans.create(
                group=vlan_group.id,
                vid=vid,
                name=clean_vlan_name,
                tenant=tenant.id,
                role=role_obj.id if role_obj else None,
                status="active",
            )
            by_vid[vid] = nb_vlan
            by_name_lower[clean_vlan_name.lower()] = nb_vlan
        else:
            changed = False
            if (is_router or nb_vlan.name.startswith("VLAN-")) and not clean_vlan_name.startswith("VLAN-"):
                if nb_vlan.name.lower() != clean_vlan_name.lower():
                    nb_vlan.name = clean_vlan_name
                    by_name_lower[clean_vlan_name.lower()] = nb_vlan
                    changed = True
            if role_obj and getattr(nb_vlan.role, "id", None) != role_obj.id:
                nb_vlan.role = role_obj.id
                changed = True
            if changed:
                print(f"[~] Aktualizuję VLAN {vid} ({nb_vlan.name}) w {site.name}")
                nb_vlan.save()

        vid_to_nb_vlan[vid] = nb_vlan
        netbox_vlans[if_name] = nb_vlan

    for if_name, v_info in parsed["vlans"].items():
        if v_info["vid"] in vid_to_nb_vlan:
            netbox_vlans[if_name] = vid_to_nb_vlan[v_info["vid"]]

    # 2. Synchronizacja portów fizycznych, tuneli L2 EoIP oraz przypisanie Bridge i VLAN-ów (L2)
    existing_ifaces = sync_device_l2_ports_and_vlans(device, parsed, vid_to_nb_vlan)

    for if_name, v_info in parsed["vlans"].items():
        if parsed["ext"] == ".swb":
            continue
        nb_vlan_if = existing_ifaces.get(if_name)
        if not nb_vlan_if:
            nb_vlan_if = nb.dcim.interfaces.create(
                device=device.id,
                name=if_name,
                type="virtual",
                description=safe_desc(v_info.get("comment", "")),
            )
            existing_ifaces[if_name] = nb_vlan_if

        parent_if_obj = existing_ifaces.get(v_info.get("parent", ""))
        nb_vlan_obj = vid_to_nb_vlan.get(v_info["vid"])
        update_interface_vlan_assignment(
            nb_vlan_if,
            mode="access" if nb_vlan_obj else None,
            untagged_vlan_obj=nb_vlan_obj,
            tagged_vlan_objs=[],
            parent_id=parent_if_obj.id if parent_if_obj else None,
            comment=v_info.get("comment", "") if v_info.get("comment", "") else None,
        )

    wg_ifaces_with_peers = {p["interface"] for p in parsed["wg_peers"]}
    valid_ip_ids_for_device = set()
    vpn_interfaces_map = {}
    candidate_primary_ips = []
    has_global_mgmt_ip = False

    # 3. Synchronizacja adresów IP i Prefiksów (L3)
    for ip_entry in parsed["ips"]:
        ip_iface = ipaddress.ip_interface(ip_entry["address"])
        network_str = str(ip_iface.network)
        if_name = ip_entry["interface"]

        mgmt_supernet = match_global_mgmt_network(ip_iface.ip)

        if if_name in parsed["wg_interfaces"] and if_name not in wg_ifaces_with_peers and not mgmt_supernet:
            print(f"[!] Pomijam nieużywany adres tunelu {ip_iface} na {if_name} (brak peerów WireGuard)")
            continue

        nb_iface = existing_ifaces.get(if_name) or safe_first(nb.dcim.interfaces, device_id=device.id, name=if_name)
        if not nb_iface:
            nb_iface = nb.dcim.interfaces.create(
                device=device.id, name=if_name, type="virtual"
            )
            existing_ifaces[if_name] = nb_iface

        # A) Adres Centralnej Sieci Zarządzania (Global VRF)
        if mgmt_supernet:
            has_global_mgmt_ip = True
            wg_addr_str = f"{ip_iface.ip}/{mgmt_supernet.prefixlen}"
            mgmt_desc = safe_desc(f"{identity} (WG MGMT)")

            existing_ips = [
                ip
                for ip in nb.ipam.ip_addresses.filter(address=str(ip_iface.ip))
                if getattr(ip, "vrf", None) is None
            ]
            nb_ip = existing_ips[0] if existing_ips else None

            if not nb_ip:
                print(f"[+] Rejestruję IP Zarządzania (Global): {wg_addr_str}")
                nb_ip = nb.ipam.ip_addresses.create(
                    address=wg_addr_str,
                    status="active",
                    tenant=tenant.id,
                    assigned_object_type="dcim.interface",
                    assigned_object_id=nb_iface.id,
                    description=mgmt_desc,
                )
            else:
                safe_reassign_ip_to_interface(
                    nb_ip,
                    target_iface=nb_iface,
                    target_device=device,
                    new_address_str=wg_addr_str,
                    new_tenant_id=tenant.id,
                    new_desc=mgmt_desc,
                )

            valid_ip_ids_for_device.add(nb_ip.id)
            candidate_primary_ips.append((100, nb_ip, nb_iface))
            continue

        # B) Adresy w VRF Klienta
        vpn_role = classify_vpn_type(network_str, if_name, parsed)
        is_vpn = vpn_role is not None
        is_this_vpn_hub = is_vpn and (ip_iface.ip == ip_iface.network.network_address + 1)

        linked_vlan = netbox_vlans.get(if_name)
        if not linked_vlan and not is_vpn and ".50." in network_str:
            linked_vlan = vid_to_nb_vlan.get(50) or safe_first(nb.ipam.vlans, group_id=vlan_group.id, vid=50)

        role_name = zgadnij_role_podsieci(
            vid=linked_vlan.vid if linked_vlan else None,
            network_str=network_str,
            if_name=if_name,
            comment=ip_entry["comment"],
            parsed=parsed,
        )
        role_obj = get_or_create_role(role_name)

        if linked_vlan and role_obj and getattr(linked_vlan, "role", None) is None:
            linked_vlan.role = role_obj.id
            linked_vlan.save()

        if not is_vpn and role_name in ("LAN / Biuro", "Management", "CCTV / Monitoring", "IoT / RCP / Automatyka", "VoIP / Telefonia"):
            ensure_client_container_prefix(vrf, tenant, ip_iface)

        # 3a. Synchronizacja Prefiksu
        nb_prefix = None
        if ip_iface.network.prefixlen < 32:
            matching_prefixes = list(nb.ipam.prefixes.filter(prefix=network_str, vrf_id=vrf.id))

            if is_vpn:
                nb_prefix = matching_prefixes[0] if matching_prefixes else None
            else:
                for p in matching_prefixes:
                    if get_prefix_site_id(p) == site.id:
                        nb_prefix = p
                        break

            if not nb_prefix:
                print(
                    f"[+] Tworzę podsieć {network_str} w VRF {vrf.name} "
                    f"({'Tunel VPN' if is_vpn else 'Oddział: ' + site.name}, Rola: {role_name})"
                )
                prefix_payload = {
                    "prefix": network_str,
                    "vrf": vrf.id,
                    "tenant": tenant.id,
                    "vlan": linked_vlan.id if linked_vlan else None,
                    "role": role_obj.id if role_obj else None,
                    "status": "active",
                    "description": safe_desc(
                        f"Pula VPN ({if_name})"
                        if is_vpn
                        else f"{site.name} ({if_name})"
                    ),
                }
                if is_vpn and not is_this_vpn_hub:
                    nb_prefix = nb.ipam.prefixes.create(**prefix_payload)
                else:
                    try:
                        nb_prefix = nb.ipam.prefixes.create(
                            **prefix_payload, scope_type="dcim.site", scope_id=site.id
                        )
                    except pynetbox.core.query.RequestError:
                        nb_prefix = nb.ipam.prefixes.create(
                            **prefix_payload, site=site.id
                        )
            else:
                pfx_changed = False
                if not is_vpn or is_this_vpn_hub or getattr(nb_prefix, "role", None) is None:
                    if role_obj and getattr(nb_prefix.role, "id", None) != role_obj.id:
                        nb_prefix.role = role_obj.id
                        pfx_changed = True
                if linked_vlan and getattr(nb_prefix.vlan, "id", None) != linked_vlan.id:
                    nb_prefix.vlan = linked_vlan.id
                    pfx_changed = True
                if pfx_changed:
                    print(f"[~] Aktualizuję rolę/VLAN podsieci {network_str} -> Rola: {role_name}")
                    nb_prefix.save()

                if is_this_vpn_hub and get_prefix_site_id(nb_prefix) != site.id:
                    if set_prefix_site_scope(nb_prefix, site.id):
                        print(f"[~] Przypisuję Scope głównego oddziału ({site.name}) dla puli VPN {network_str}")

        # 3b. Synchronizacja Adresu IP urządzenia
        existing_vrf_ips = list(nb.ipam.ip_addresses.filter(address=str(ip_iface), vrf_id=vrf.id))
        dev_iface_ids = {i.id for i in existing_ifaces.values()}

        nb_local_ip = None
        for cand_ip in existing_vrf_ips:
            assigned_id = getattr(cand_ip, "assigned_object_id", None)
            if assigned_id in dev_iface_ids or assigned_id is None:
                nb_local_ip = cand_ip
                break

        expected_desc = safe_desc(ip_entry["comment"] or f"{short_dev_label(identity)} ({if_name})")
        if not nb_local_ip:
            print(f"[+] Rejestruję IP urządzenia: {ip_iface} ({identity} -> {if_name})")
            nb_local_ip = nb.ipam.ip_addresses.create(
                address=str(ip_iface),
                vrf=vrf.id,
                tenant=tenant.id,
                status="active",
                assigned_object_type="dcim.interface",
                assigned_object_id=nb_iface.id,
                description=expected_desc,
            )
        else:
            safe_reassign_ip_to_interface(
                nb_local_ip,
                target_iface=nb_iface,
                target_device=device,
                new_tenant_id=tenant.id,
                new_desc=expected_desc,
            )

        valid_ip_ids_for_device.add(nb_local_ip.id)
        prio = calculate_ip_priority(ip_iface, if_name, role_name, is_router)
        candidate_primary_ips.append((prio, nb_local_ip, nb_iface))

        if is_vpn and is_router:
            vpn_interfaces_map[if_name] = {
                "nb_iface": nb_iface,
                "ip_iface": ip_iface,
                "nb_prefix": nb_prefix,
            }

    # 4. Ustaw najlepszy Primary IPv4 według priorytetu
    if candidate_primary_ips:
        candidate_primary_ips.sort(key=lambda x: x[0], reverse=True)
        best_prio, best_ip, best_iface = candidate_primary_ips[0]
        if getattr(device.primary_ip4, "id", None) != best_ip.id:
            print(f"[~] Ustawiam Primary IPv4 dla {identity}: {best_ip.address} ({best_iface.name})")
            device.primary_ip4 = best_ip.id
            device.save()

    # 4b. Automatyczne otagowanie RouterOS pod Oxidized (wyłącznie .rsc; SwOS nie ma SSH)
    if (
        AUTO_TAG_OXIDIZED
        and parsed["ext"] == ".rsc"
        and OXIDIZED_TAG_NAME
        and (not OXIDIZED_TAG_REQUIRE_MGMT_IP or has_global_mgmt_ip)
    ):
        ox_tag = get_or_create_tag(OXIDIZED_TAG_NAME)
        ensure_device_tag(device, ox_tag)

    # 5. POŁĄCZ KABLAMI PORTY L2 W ODDZIALE ORAZ TUNELE VPN MIĘDZY ROUTERAMI
    link_site_l2_devices(device, site, existing_ifaces)
    active_sub_ifaces = set()
    if is_router and vpn_interfaces_map:
        active_sub_ifaces = link_router_tunnels(device, vrf, tenant, parsed, vpn_interfaces_map)

    # 6. WYCZYŚĆ STARE ADRESY IP ORAZ WYCOFANE INTERFEJSY WIRTUALNE (np. dawny wireguard1 lub vlan110)
    if CLEANUP_REMOVED_IPS:
        for iface_obj in list(nb.dcim.interfaces.filter(device_id=device.id)):
            for old_ip in nb.ipam.ip_addresses.filter(assigned_object_id=iface_obj.id):
                if old_ip.id not in valid_ip_ids_for_device:
                    print(f"[-] Usuwam nieaktualny adres IP z {identity}: {old_ip.address}")
                    if getattr(device.primary_ip4, "id", None) == old_ip.id:
                        device.primary_ip4 = None
                        device.save()
                    old_ip.delete()

    if CLEANUP_REMOVED_VIRTUAL_INTERFACES and parsed["ext"] == ".rsc":
        valid_virtual_names = (
            set(parsed.get("bridges", {}).keys())
            | set(parsed.get("vlans", {}).keys())
            | set(parsed.get("eoips", {}).keys())
            | set(parsed.get("vpn_interfaces", set()))
            | {ip_e["interface"] for ip_e in parsed.get("ips", [])}
            | active_sub_ifaces
        )
        for iface_obj in list(nb.dcim.interfaces.filter(device_id=device.id)):
            if_type_val = getattr(iface_obj.type, "value", "")
            if if_type_val in ("virtual", "bridge") and iface_obj.name not in valid_virtual_names:
                try:
                    print(f"[-] Usuwam wycofany interfejs wirtualny z {identity}: {iface_obj.name}")
                    iface_obj.delete()
                except Exception:
                    pass

    return True


# =====================================================================
# 10. AUTOMATYCZNY IMPORT ZBIORCZY
# =====================================================================
def process_batch(target_dir=".", archive_files=None, only_new=False):
    init_netbox()
    do_archive = ARCHIVE_IMPORTED_FILES if archive_files is None else archive_files
    files = sorted(
        glob.glob(os.path.join(target_dir, "*.rsc"))
        + glob.glob(os.path.join(target_dir, "*.swb"))
    )

    if not files:
        print(f"[!] Brak plików .rsc lub .swb w katalogu: {os.path.abspath(target_dir)}")
        return

    parsed_items = []
    for fpath in files:
        try:
            parsed_items.append(pre_parse_backup(fpath))
        except Exception as e:
            print(f"[!] Błąd odczytu pliku {fpath}: {e}")

    parsed_items.sort(
        key=lambda x: (
            0 if x["is_router"] else 1,
            0 if x.get("is_vpn_hub") else 1,
            0 if "CORE" in x["identity"].upper() else 1,
            0 if x["ext"] == ".rsc" else 1,
            x["identity"],
        )
    )

    routers_count = sum(1 for x in parsed_items if x["is_router"])
    switches_count = len(parsed_items) - routers_count

    print("=" * 75)
    print(
        f"ZNALEZIONO PLIKÓW: {len(parsed_items)} "
        f"(Routery w 1. kolejności: {routers_count}, Switche w 2. kolejności: {switches_count})"
    )
    print("=" * 75)

    archive_dir = os.path.join(target_dir, ARCHIVE_DIR_NAME)
    if do_archive:
        os.makedirs(archive_dir, exist_ok=True)

    for item in parsed_items:
        try:
            processed = import_parsed_to_netbox(item, only_new=only_new)
            if do_archive and processed:
                dest = os.path.join(archive_dir, os.path.basename(item["filepath"]))
                shutil.move(item["filepath"], dest)
                print(f"[>] Przeniesiono plik do: {dest}")
        except Exception as e:
            print(f"[X] BŁĄD podczas importu {item['filepath']}: {e}")

    print("\n[✓] Zakończono przetwarzanie wszystkich plików!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Idempotentny importer konfiguracji MikroTik (.rsc / .swb) do NetBox (Source of Truth)."
    )
    parser.add_argument(
        "folder",
        nargs="?",
        default=".",
        help="Katalog zawierający pliki .rsc (RouterOS) i/lub .swb (SwOS). Domyślnie bieżący katalog.",
    )
    parser.add_argument(
        "--no-archive",
        action="store_true",
        help="Nie przenoś przetworzonych plików do podkatalogu archiwum (nadpisuje ARCHIVE_IMPORTED_FILES).",
    )
    parser.add_argument(
        "--only-new",
        action="store_true",
        help="Tryb Day-1 Safe: pomija urządzenia już istniejące w NetBoxie ze statusem 'active' (sprawdzane najpierw po SN, potem po nazwie).",
    )
    args = parser.parse_args()
    process_batch(
        args.folder,
        archive_files=False if args.no_archive else None,
        only_new=args.only_new,
    )
