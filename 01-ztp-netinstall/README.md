# 01 — Automatyczny Netinstall (ZTP): `systemd` + `.dpk` + Telegram

Wrapper w Pythonie ([`autonetinstall.py`](autonetinstall.py)) uruchamiany jako usługa `systemd`, który automatyzuje wgrywanie systemu RouterOS przez `netinstall-cli` wraz z customową paczką brandingową (`.dpk`).

## Jak działa provisioning ZTP

1. Skrypt [`autonetinstall.py`](autonetinstall.py) uruchamia w pętli `./netinstall-cli -i <NETINSTALL_IFACE> [-r <BRANDING_PKG>] <pliki .npk>`.
2. Przy starcie sprawdza obecność `./netinstall-cli` oraz obrazów zdefiniowanych w słowniku `ARCH_FILES` (`mipsbe`, `mmips`, `arm`, `arm64`, `smips`) — brakujące architektury są pomijane, ale co najmniej jeden plik `.npk` musi być dostępny.
3. Jeśli w katalogu roboczym znajduje się paczka brandingowa (`BRANDING_PKG`, domyślnie `custom-branding.dpk`), jest przekazywana flagą `-r`. Zawiera ona zaszyty skrypt startowy `default-configuration` (zanonimizowany przykład dla modeli 5-portowych znajduje się w [`ztp-bootstrap.rsc.example`](ztp-bootstrap.rsc.example)): po restarcie router odczytuje swój numer seryjny (SN), odpytuje zewnętrzne *Provisioning API* (z ponawianiem co minutę przez `AutoProvisioningSched`, dopóki pobrana konfiguracja docelowa nie usunie schedulera), pobiera docelową konfigurację, zestawia tunel WireGuard do Core Routera i automatycznie trafia do NetBoxa. Gdy plik `.dpk` nie istnieje, instalowany jest czysty RouterOS.
4. Skrypt parsuje na bieżąco stdout/stderr `netinstall-cli` i wysyła powiadomienia HTML na Telegram (start serwera ZTP, przydzielenie IP, wykryty MAC routera, formatowanie dysku, wysyłanie pakietów, zakończenie instalacji, błędy krytyczne). Jeśli `TELEGRAM_BOT_TOKEN` lub `TELEGRAM_CHAT_ID` są puste, powiadomienia są automatycznie wyłączone.

> [!WARNING]
> **Izolowany VLAN (BOOTP):**
> `netinstall-cli` wykorzystuje rozgłoszeniowy protokół BOOTP (UDP 67/68). Interfejs wskazany w `NETINSTALL_IFACE` musi pracować w **dedykowanym, odizolowanym VLAN-ie serwisowym** bez produkcyjnego serwera DHCP, aby uniknąć kolizji adresacji w sieci produkcyjnej.

## Wymagania

* Linux (Debian) z uprawnieniami `root` (wymagane przez `netinstall-cli` oraz weryfikowane przez `os.geteuid() != 0` w `autonetinstall.py`).
* Python 3 oraz pakiety z [`requirements.txt`](requirements.txt): `requests>=2.31.0`, `python-dotenv>=1.0.0`.
* Binarium `netinstall-cli` ze strony MikroTik (z prawem wykonywania `chmod +x`).
* Obrazy `routeros-*.npk` dla obsługiwanych architektur (nazwy plików w katalogu muszą zgadzać się ze słownikiem `ARCH_FILES` w [`autonetinstall.py`](autonetinstall.py)) oraz opcjonalnie paczka brandingowa `.dpk`.

## Zmienne środowiskowe (`.env.example`)

Szablon w [`.env.example`](.env.example):

| Zmienna | Domyślna wartość | Opis |
| :--- | :--- | :--- |
| `NETINSTALL_IFACE` | `ens19` | Nazwa interfejsu sieciowego wpiętego w izolowany VLAN ZTP |
| `BRANDING_PKG` | `custom-branding.dpk` | Nazwa pliku paczki brandingowej `.dpk` przekazywanej przez `-r` |
| `TELEGRAM_BOT_TOKEN` | *(opcjonalna)* | Token bota Telegram do powiadomień o postępie instalacji |
| `TELEGRAM_CHAT_ID` | *(opcjonalna)* | ID czatu lub grupy Telegram |

## Instalacja i uruchomienie usługi `systemd`

Szablon unitu [`autonetinstall.service.example`](autonetinstall.service.example) zakłada katalog roboczy `/opt/ztp-netinstall`, uruchomienie jako `User=root`, ścieżkę `/opt/ztp-netinstall/.venv/bin/python` oraz identyfikator logów `autonetinstall`.

```bash
sudo mkdir -p /opt/ztp-netinstall
# Skopiuj zawartość katalogu 01-ztp-netinstall/ oraz pliki netinstall-cli, *.npk i custom-branding.dpk do /opt/ztp-netinstall
cd /opt/ztp-netinstall
sudo chmod +x netinstall-cli

python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
# Uzupełnij w .env interfejs NETINSTALL_IFACE, nazwę BRANDING_PKG i opcjonalne dane Telegram

sudo cp autonetinstall.service.example /etc/systemd/system/autonetinstall.service
sudo systemctl daemon-reload
sudo systemctl enable --now autonetinstall.service

# Podgląd logów na żywo:
sudo journalctl -u autonetinstall -f
```
