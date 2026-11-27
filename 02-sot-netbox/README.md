# 02 — NetBox: importer konfiguracji i audyt spójności

Katalog zawiera dwa narzędzia w Pythonie uruchamiane **ręcznie z linii poleceń (CLI) na serwerze z NetBoxem**. Nowe routery przechodzące przez ZTP i autorskie *Provisioning API* trafiają do NetBoxa automatycznie — tutejsze skrypty służą do importu istniejących urządzeń, dodawania switchy SwOS, uzupełniania braków oraz kontroli spójności:

1. [`sync_mikrotik_to_netbox.py`](sync_mikrotik_to_netbox.py) — idempotentny importer konfiguracji RouterOS (`.rsc`) oraz backupów switchy SwOS (`.swb`, np. CSS326/CRS328) do **NetBox**.
2. [`audit_wg_reconciliation.py`](audit_wg_reconciliation.py) — skrypt audytowy **Read-Only** porównujący peerów WireGuard na Core Routerze, bazę NetBox oraz stan kopii w Oxidized (`/nodes.json`).

Oba skrypty działają wyłącznie wobec lokalnego REST API NetBoxa (oraz opcjonalnie wykonują HTTP GET na `/nodes.json` w Oxidized). Na serwerze z NetBoxem nie ma żadnych kluczy SSH ani połączeń sieciowych z routerami.

## Wymagania i przygotowanie środowiska

* Python `3.10+`
* Zależności z [`requirements.txt`](requirements.txt): `pynetbox>=7.5.0` (wymagane m.in. do obsługi **API Token v2** `nbt_...` w NetBox v4.5+) oraz `python-dotenv>=1.0.0`.

```bash
cd 02-sot-netbox
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
```

## Zmienne środowiskowe (`.env.example`)

Wszystkie parametry z [`.env.example`](.env.example):

| Zmienna | Domyślna wartość | Opis |
| :--- | :--- | :--- |
| `NETBOX_URL` | `http://netbox.local:8000` | Adres URL instancji NetBox |
| `NETBOX_TOKEN` | *(wymagana)* | Token API NetBoxa (zapis dla importera, Read-Only wystarczy dla audytu) |
| `NETBOX_VERIFY_SSL` | `true` | Weryfikacja certyfikatu TLS dla połączeń HTTPS |
| `MGMT_VPN_ROLE_NAME` | `Wireguard Management` | Rola prefiksów w Global VRF identyfikująca sieć zarządzania WG |
| `FALLBACK_MGMT_SUPERNET` | `10.0.0.0/22` | Zapasowa podsieć zarządzania WG, gdy brak prefiksów z powyższą rolą |
| `AUTO_SET_PLATFORM` | `true` | Automatyczne ustawianie `Platform` (`routeros` dla `.rsc`, `swos` dla `.swb`) |
| `AUTO_TAG_OXIDIZED` | `true` | Automatyczne nadawanie tagu `OXIDIZED_TAG_NAME` urządzeniom `.rsc` |
| `OXIDIZED_TAG_NAME` | `oxidized` | Nazwa tagu używanego przez dynamiczne źródło Oxidized |
| `OXIDIZED_TAG_REQUIRE_MGMT_IP` | `true` | Wymaga adresu z globalnej sieci WG MGMT przed nadaniem tagu `oxidized` |
| `ARCHIVE_IMPORTED_FILES` | `true` | Przenoszenie przetworzonych plików do podkatalogu archiwum |
| `ARCHIVE_DIR_NAME` | `zaimportowane` | Nazwa podkatalogu archiwum tworzonego w folderze źródłowym |
| `CLEANUP_REMOVED_IPS` | `true` | Usuwanie nieaktualnych adresów IP z urządzenia podczas pełnej synchronizacji |
| `CLEANUP_REMOVED_VIRTUAL_INTERFACES` | `true` | Usuwanie wycofanych interfejsów wirtualnych i bridge'y (tylko `.rsc`) |
| `OXIDIZED_URL` | *(opcjonalna)* | Domyślny adres Oxidized Web UI (np. `http://netops-mgmt.local:8888`) dla audytu |

---

## Narzędzie 1: `sync_mikrotik_to_netbox.py`

Skrypt przetwarza pliki z podanego katalogu w deterministycznej kolejności (najpierw routery i huby VPN, następnie switche) i idempotentnie odtwarza:

* **Tenancy, VRF i Site:** tworzenie `Tenant`, `VRF` (z `enforce_unique=False` dla powtarzalnych podsieci LAN między klientami) oraz `Site` na podstawie nazewnictwa urządzenia.
* **DCIM, porty L2 i kable:** dopasowanie lub tworzenie `Device Type` z wnioskowaniem portów, dekodowanie VLAN-ów i trybów portów (`access` / `tagged`) z `.rsc` i binarnych/hexowych masek `.swb`, a także automatyczne łączenie portów trunkowych w oddziale obiektami `dcim.cable`.
* **IPAM, `Primary IPv4` i VPN:** klasyfikacja ról podsieci i priorytetyzacja adresów — adres z globalnej sieci zarządzania WireGuard otrzymuje najwyższy priorytet (`100`) i staje się `Primary IPv4`. Dla routerów z sieciami VPN tworzone są obiekty `vpn.tunnel` i `tunnel_terminations`.
* **Gotowość pod Oxidized:** ustawienie `Platform` (`routeros` / `swos`) oraz dopisanie tagu `oxidized` wyłącznie urządzeniom `.rsc` (switche SwOS nie obsługują SSH).

### Tryby pracy i flagi CLI

* `folder` *(opcjonalny argument pozycyjny, domyślnie `.`)* — katalog z plikami `.rsc` i/lub `.swb`.
* **Tryb pełnej synchronizacji (domyślny):** pełna synchronizacja całej floty oraz czyszczenie starych IP / wycofanych interfejsów wirtualnych.
* **`--only-new` (tryb bezpieczny):** wyszukuje urządzenie w NetBoxie **najpierw po numerze seryjnym (`serial`)**, a dopiero w drugiej kolejności po nazwie (`name`). Jeśli obiekt istnieje już ze statusem **`active`**, zostaje pominięty bez nadpisywania SoT i bez przenoszenia pliku do archiwum.
* **`--no-archive`:** wyłącza przenoszenie przetworzonych plików do podkatalogu `ARCHIVE_DIR_NAME` (nadpisuje `ARCHIVE_IMPORTED_FILES`).

```bash
# Test pełnej synchronizacji bez przenoszenia plików do archiwum:
.venv/bin/python sync_mikrotik_to_netbox.py /sciezka/do/eksportow --no-archive

# Tryb bezpieczny (dodaje tylko nowe lub nieaktywne urządzenia, pomija 'active'):
.venv/bin/python sync_mikrotik_to_netbox.py /sciezka/do/eksportow --only-new --no-archive

# Standardowy import wsadowy z archiwizacją przetworzonych plików:
.venv/bin/python sync_mikrotik_to_netbox.py /sciezka/do/eksportow
```

---

## Narzędzie 2: `audit_wg_reconciliation.py`

Skrypt tylko do odczytu (Read-Only), który porównuje stan z trzech źródeł: peerów WireGuard na Core Routerze, bazy NetBox oraz listy kopii w Oxidized (`/nodes.json`).

Dopasowanie peera WG do NetBoxa przebiega w kolejności: adres IP zarządzania WG -> numer seryjny `serial` (z komentarza peera lub z `*.sn.mynetname.net`) -> nazwa peera. Parser automatycznie skleja linie złamane przez terminal i obsługuje kodowania UTF-8, UTF-8-BOM oraz UTF-16 (Windows/PowerShell).

### Pobranie danych i uruchomienie

1. Na Core Routerze wykonaj zrzut peerów zarządzania i zapisz do pliku `wg_peers.txt`:
   ```routeros
   /interface/wireguard/peers/print terse without-paging where interface=wg-mgmt
   ```
2. Uruchom audyt (opcjonalnie z `--oxidized-url`, jeśli Oxidized jest dostępny po sieci):
   ```bash
   .venv/bin/python audit_wg_reconciliation.py wg_peers.txt \
     --stale-days 7 \
     --oxidized-url http://netops-mgmt.local:8888 \
     --csv raport_rozjazdow.csv
   ```

### Flagi CLI

| Argument / Flaga | Domyślna wartość | Opis |
| :--- | :--- | :--- |
| `peers_file` | *(wymagany)* | Ścieżka do pliku ze zrzutem `/interface/wireguard/peers/print terse ...` |
| `--stale-days` | `7` | Próg dni od `last-handshake`, powyżej którego peer uznawany jest za nieaktywny |
| `--oxidized-url` | `OXIDIZED_URL` z `.env` | Opcjonalny adres Oxidized Web UI do odpytania `/nodes.json` |
| `--csv` | *(brak)* | Opcjonalna ścieżka zapisu zbiorczego raportu CSV (`utf-8-sig`) |

### 5 kategorii w raporcie

| Kategoria | Warunek wykrycia | Zalecana akcja |
| :--- | :--- | :--- |
| `1_WG_ACTIVE_MISSING_IN_NETBOX` | Aktywny peer WG (świeży handshake), brak urządzenia w NetBoxie | Pobrać `.rsc` i dodać przez `sync_mikrotik_to_netbox.py --only-new` |
| `2_WG_ACTIVE_WRONG_NB_STATUS` | Aktywny peer WG, status w NetBoxie inny niż `active` (np. `staged`) | Zmienić status urządzenia w NetBoxie na `active` |
| `3_WG_STALE_OR_DISABLED` | `disabled=yes`, brak handshake lub handshake starszy niż `--stale-days` | Zweryfikować, czy czeka na montaż (`staged`), czy wycofać (NetBox `offline` + WG `disabled=yes`) |
| `4_NETBOX_ACTIVE_MISSING_IN_WG` | Urządzenie `active` z IP WG MGMT w NetBoxie, brak peera na Core Routerze | Zmienić status w NetBoxie na `offline` |
| `5_OXIDIZED_METADATA_OR_BACKUP_ISSUE` | Aktywny router (nie-SwOS) z IP WG MGMT: brak tagu `oxidized`, zły slug platformy, brak w `/nodes.json` lub `last_status != success` | Uzupełnić tag/platformę w NetBoxie, wykonać `/reload` w Oxidized lub sprawdzić dostęp SSH |
