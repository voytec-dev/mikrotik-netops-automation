# 03 — Wersjonowanie konfiguracji: Oxidized (Docker) + NetBox REST API

Kontenerowe wdrożenie **Oxidized** (`oxidized/oxidized:latest`) na serwerze zarządzania. Kontener pobiera listę routerów dynamicznie z REST API NetBoxa, łączy się z urządzeniami po tunelu WireGuard (`interval: 3600`, `threads: 10`, `timeout: 20`, `retries: 3`), wykonuje eksport z `remove_secret: false` (`/export show-sensitive`) i zapisuje historię zmian w lokalnym repozytorium Git (`/home/oxidized/.config/oxidized/oxidized.git`).

## Integracja z REST API NetBoxa (`source: http`)

Domyślna konfiguracja ([`oxidized/config.example`](oxidized/config.example)) korzysta ze źródła `http`:

* **`url`**: `http://netbox.local:8000/api/dcim/devices/?status=active&tag=oxidized&has_primary_ip=true` — pobiera wyłącznie aktywne urządzenia z przypisanym `Primary IPv4` i tagiem `oxidized` (nadawanym automatycznie routerom `.rsc` przez `02-sot-netbox`).
* **`hosts_location: results`** oraz **`pagination: true`** (`pagination_key_name: next`) — poprawne przechodzenie przez stronicowane odpowiedzi NetBox API.
* **`map`**: `name: name`, `ip: primary_ip4.address` (Oxidized automatycznie odcina maskę CIDR przed zestawieniem sesji SSH), `model: platform.slug`, `group: tenant.name`.
* **`model_map`**: mapuje slugi `routeros` oraz `mikrotik-routeros` na model `routeros`.
* **`resolve_dns: false`**: łączenie bezpośrednio po adresie IP bez zapytań DNS.

W NetBoxie 4.5+ (Token v2 z prefiksem `nbt_...`) nagłówek `Authorization` wymaga prefiksu `Bearer` (dla starszych wersji z Token v1 używa się `Token`).

Test łączności z NetBox API przed uruchomieniem kontenera:

```bash
# NetBox v4.5+ (Token v2):
curl -sS -H "Authorization: Bearer nbt_YOUR_NETBOX_READONLY_TOKEN" \
     -H "Accept: application/json" \
     "http://netbox.local:8000/api/dcim/devices/?status=active&tag=oxidized&has_primary_ip=true" | head -c 500
```

## Klucz SSH (RSA 4096 PEM) i uprawnienia kontenera (UID 30000)

Oficjalny obraz `oxidized/oxidized` działa w kontenerze jako użytkownik o **UID/GID `30000`**. Do uwierzytelniania na RouterOS v6 i v7 wymagany jest klucz **RSA 4096-bit w formacie PEM**:

```bash
cd 03-config-versioning-oxidized
cp oxidized/config.example oxidized/config
# Uzupełnij w oxidized/config adres NetBoxa i token API tylko do odczytu

ssh-keygen -t rsa -b 4096 -m PEM -f oxidized/oxidized_rsa -N ""
chmod 600 oxidized/oxidized_rsa
sudo chown -R 30000:30000 oxidized/
```

## Minimalne uprawnienia na MikroTiku (`ssh,read,sensitive`)

Oxidized korzysta z osobnego konta `oxidized` i własnego klucza SSH. Uprawnienie `sensitive` jest wymagane przy `remove_secret: false`, aby eksport zawierał pełną konfigurację wraz z kluczami WireGuard i sekretami, bez prawa zapisu czy dostępu przez Winbox/FTP:

```routeros
/user group add name=oxidized policy=ssh,read,sensitive
/user add name=oxidized group=oxidized password="USTAW_LOSOWE_DLUGIE_HASLO"
/user ssh-keys import public-key-file=oxidized_rsa.pub user=oxidized
```

## Uruchomienie przez `docker compose`

Plik [`docker-compose.yml`](docker-compose.yml) montuje katalog `./oxidized` pod `/home/oxidized/.config/oxidized` i wystawia port `8888:8888`:

```bash
docker compose up -d
docker compose logs -f oxidized
```

* **Web UI i API Oxidized** działają pod portem `8888` (endpoint `/nodes.json` jest wykorzystywany przez `audit_wg_reconciliation.py`, a `/reload` wymusza odświeżenie listy urządzeń z NetBoxa). Ponieważ `remove_secret: false` zapisuje w eksportach pełne konfiguracje z sekretami, dostęp do portu `8888` na produkcji jest ograniczony na firewallu wyłącznie do sieci administracyjnej oraz serwera z NetBoxem (który odpytuje `/nodes.json`).
* **Tryb awaryjny (bez NetBoxa):** skopiuj [`oxidized/router.db.example`](oxidized/router.db.example) do `oxidized/router.db` i przełącz w `oxidized/config` źródło na zakomentowany **Wariant 2** (`source: csv`).
