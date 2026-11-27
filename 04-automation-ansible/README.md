# 04 — Zarządzanie flotą MikroTik przez Ansible

Moduł Ansible pobierający listę routerów z NetBoxa (wtyczka `netbox.netbox.nb_inventory`). Zarządza aktywnymi routerami **RouterOS v7.12+** po tunelu WireGuard przez `network_cli` (`libssh`, kolekcja `community.routeros`), korzystając z osobnego konta `ansible` (ograniczonego do IP serwera zarządzania) oraz klucza SSH **Ed25519**.

## Wymagania i instalacja

* Debian z Pythonem `3.10+`
* Pakiety systemowe do budowy `ansible-pylibssh`: `python3-venv`, `python3-dev`, `libssh-dev`, `gcc`
* Zależności Pythona ([`requirements.txt`](requirements.txt)) oraz kolekcje Ansible ([`collections/requirements.yml`](collections/requirements.yml))

```bash
sudo apt-get update
sudo apt-get install -y python3-venv python3-dev libssh-dev gcc

mkdir -p ~/ansible-mikrotik
# Skopiuj zawartość katalogu 04-automation-ansible/ do ~/ansible-mikrotik
cd ~/ansible-mikrotik

python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
.venv/bin/ansible-galaxy collection install -r collections/requirements.yml

cp .env.example .env
cp inventory/netbox.yml.example inventory/netbox.yml
cp inventory/group_vars/all.yml.example inventory/group_vars/all.yml
chmod 600 .env
```

## Konfiguracja inventory i zmiennych (`.env`)

Konfiguracja inventory ([`inventory/netbox.yml.example`](inventory/netbox.yml.example)) pobiera z NetBoxa wyłącznie urządzenia spełniające warunki `status=active`, `platform=routeros` oraz `has_primary_ip=true` (pomija switche SwOS) i grupuje je po `tenants`, `sites`, `device_roles` oraz `tags`.

Konfiguracja domyślnie używa **tokenu Read-Only NetBox v4.5+ (Token v2 `nbt_...`, nagłówek `Bearer`)**. Dla starszych wersji NetBoxa (Token v1) w `inventory/netbox.yml.example` znajduje się zakomentowany wariant ze zwykłym stringiem.

| Zmienna | Domyślna wartość | Opis |
| :--- | :--- | :--- |
| `NETBOX_API` | `http://netbox.local:8000` | Adres URL instancji NetBox (czytany natywnie przez `nb_inventory`) |
| `NETBOX_TOKEN` | *(wymagana)* | Token API NetBoxa tylko do odczytu (`nbt_...`) |
| `ANSIBLE_MGMT_IP` | `10.0.10.254/32` | Adres IP serwera zarządzania wpisywany w `address=` konta `ansible` na routerach |
| `ANSIBLE_PUBKEY_FILE` | `./ansible_mikrotik_ed25519.pub` | Ścieżka do pliku klucza publicznego `.pub` wgrywanego na routery podczas bootstrapu |

Weryfikacja inventory przed uruchomieniem playbooków:

```bash
source .venv/bin/activate
source .env

ansible-inventory --graph
ansible all --list-hosts
ansible-inventory --host <NAZWA_ROUTERA>
```

> Awaryjnie (gdy NetBox API jest niedostępne) można użyć statycznego pliku [`inventory/hosts.yml.example`](inventory/hosts.yml.example) po skopiowaniu do `inventory/hosts.yml` i wskazaniu flagą `-i inventory/hosts.yml`.

## Playbooki

### 1. `playbooks/bootstrap_ansible.yml`

Jednorazowe przygotowanie dostępu dla Ansible na routerach z RouterOS v7 (np. logując się poświadczeniami admina lub konta RADIUS):

* sprawdza lokalnie obecność `ANSIBLE_MGMT_IP` i pliku `.pub`,
* idempotentnie tworzy grupę `ansible` (`policy=ssh,read,write,policy,test,sensitive,reboot` — bez Winbox/Web/FTP/API),
* tworzy użytkownika `ansible` z losowym 24-znakowym hasłem i ograniczeniem źródłowego IP (`address=<ANSIBLE_MGMT_IP>`),
* wgrywa i importuje klucz publiczny przez CLI (`/file/add` -> `/user/ssh-keys/import` -> `/file/remove`) bez włączania FTP/SCP oraz potwierdza przypisanie klucza przez `assert`.

```bash
# Test na pojedynczym routerze (flaga SSH_AUTH_SOCK="" wymusza logowanie hasłem przy aktywnym agencie SSH):
SSH_AUTH_SOCK="" ansible-playbook playbooks/bootstrap_ansible.yml \
  -l <NAZWA_ROUTERA> \
  -e "ansible_user=<LOGIN_ADMIN_LUB_RADIUS>" -k

# Sprawdzenie dostępu już bezpośrednio z konta ansible (po kluczu SSH, bez hasła):
ansible <NAZWA_ROUTERA> -m community.routeros.command -a '{"commands": ["/system/identity/print"]}'
```

### 2. `playbooks/audit_fleet.yml`

Playbook **Read-Only** (`changed_when: false`): pobiera `/system/identity/print`, `/system/resource/print` i `/system/routerboard/print`, wyświetla podsumowanie w terminalu (oznacza `[FW UPGRADE NEEDED]`, jeśli `current-firmware != upgrade-firmware`) oraz zapisuje zbiorczy raport CSV w `reports/fleet_audit_YYYYMMDD_HHMM.csv` (w tym wiersze `UNREACHABLE` dla nieosiągalnych hostów).

```bash
# Pojedynczy router:
ansible-playbook playbooks/audit_fleet.yml -l <NAZWA_ROUTERA>

# Wybrany klient (grupa z NetBoxa):
ansible-playbook playbooks/audit_fleet.yml -l tenants_<klient>

# Cała aktywna flota RouterOS:
ansible-playbook playbooks/audit_fleet.yml
```
