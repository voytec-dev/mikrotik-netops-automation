import os
import re
import subprocess
import sys
import time
import requests
from dotenv import load_dotenv

load_dotenv()

# --- KONFIGURACJA ---
NETINSTALL_PATH = "./netinstall-cli"
INTERFACE = os.getenv("NETINSTALL_IFACE", "ens19")
BRANDING_PKG = os.getenv("BRANDING_PKG", "custom-branding.dpk")

# --- KONFIGURACJA TELEGRAM ---
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# --- PLIKI DO ZAŁADOWANIA ---
ARCH_FILES = {
    "mipsbe": "routeros-7.20.4-mipsbe.npk",
    "mmips": "routeros-7.20.4-mmips.npk",
    "arm": "routeros-7.20.4-arm.npk",
    "arm64": "routeros-7.20.6-arm64.npk",
    "smips": "routeros-7.20.4-smips.npk",
}


def log(msg, symbol="ℹ️"):
    """Wyświetla sformatowany komunikat z czasem w konsoli."""
    timestamp = time.strftime("%H:%M:%S")
    print(f"[{timestamp}] {symbol} {msg}", flush=True)


def send_telegram(text, symbol="ℹ️"):
    """Wysyła powiadomienie o postępie instalacji na Telegram."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": f"{symbol} <b>Netinstall ZTP</b>\n{text}",
        "parse_mode": "HTML",
    }

    try:
        requests.post(url, json=payload, timeout=3)
    except Exception as e:
        print(f"  ⚠️ Błąd wysyłania powiadomienia Telegram: {e}", flush=True)


def check_files():
    if not os.path.exists(NETINSTALL_PATH):
        log(f"Brak pliku wykonywalnego: {NETINSTALL_PATH}", "❌")
        sys.exit(1)

    valid_files = []
    print("\n--- SPRAWDZANIE PLIKÓW ---")
    for arch, filename in ARCH_FILES.items():
        if os.path.exists(filename):
            print(f"✅ {arch.ljust(10)} -> {filename}")
            valid_files.append(filename)
        else:
            print(f"⚠️ {arch.ljust(10)} -> BRAK PLIKU ({filename}) - Pomijam.")

    if not valid_files:
        log("Brak jakichkolwiek plików .npk! Zakończono.", "❌")
        sys.exit(1)
    print("--------------------------\n")
    return valid_files


def main_loop():
    files_to_load = check_files()
    cmd = [NETINSTALL_PATH, "-i", INTERFACE]

    if os.path.exists(BRANDING_PKG):
        cmd.extend(["-r", BRANDING_PKG])
        log(f"Załadowano pakiet startowy/branding: {BRANDING_PKG}", "⚙️")
    else:
        log(f"Brak pliku {BRANDING_PKG} (instalacja czystego RouterOS)", "⚠️")

    cmd.extend(files_to_load)

    log(f"Start serwera na interfejsie {INTERFACE}. Oczekiwanie na urządzenia...", "🚀")
    send_telegram("Serwer ZTP AKTYWNY - oczekiwanie na routery...", "🚀")

    while True:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            while True:
                line = proc.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if not line or "MSFT 5.0" in line:
                    continue

                if "Assigned" in line and "to" in line:
                    log("Router przyjął adres IP. Nawiązano połączenie.", "🤝")
                    send_telegram("Router przyjął adres IP. Nawiązano połączenie.", "🤝")

                elif "Booting device" in line:
                    mac_match = re.search(
                        r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", line
                    )
                    current_mac = mac_match.group(0).upper() if mac_match else "Nieznany"
                    log(f"Wykryto router: {current_mac}", "🔌")
                    send_telegram(
                        f"Wykryto router!\n<b>MAC:</b> <code>{current_mac}</code>\nRozpoczęto instalację RouterOS.",
                        "🔌",
                    )

                elif "Formatting" in line:
                    log("Formatowanie dysku routera...", "🧹")
                    send_telegram("Formatowanie dysku routera...", "🧹")

                elif "Sending packages" in line:
                    log("Wgrywanie pakietów RouterOS...", "📦")
                    send_telegram("Wgrywanie oprogramowania RouterOS...", "📦")

                elif "Successfully finished" in line:
                    log("SUKCES! Instalacja zakończona pomyślnie.", "✅")
                    log("Router uruchamia się ponownie. Można odłączyć.", "✂️")
                    send_telegram(
                        "<b>Instalacja zakończona pomyślnie!</b>\nMożesz odłączyć urządzenie.",
                        "✅",
                    )
                    print("\n--- GOTOWY NA KOLEJNY ROUTER ---\n")

                elif any(err in line.lower() for err in ("failed", "error", "can't")):
                    log(f"BŁĄD KRYTYCZNY: {line}", "❌")
                    send_telegram(f"<b>BŁĄD KRYTYCZNY:</b>\n<code>{line}</code>", "❌")

                else:
                    print(f"   [RAW]: {line}")

            log("Proces Netinstall zakończył działanie. Restartuję za 3s...", "🔄")
            proc.wait()
            time.sleep(3)

        except KeyboardInterrupt:
            log("Zatrzymano przez użytkownika.", "🛑")
            send_telegram("Usługa ZTP została zatrzymana ręcznie.", "🛑")
            sys.exit(0)
        except Exception as e:
            log(f"Wyjątek pętli: {e}", "❌")
            send_telegram(f"Wystąpił wyjątek w skrypcie: {e}", "❌")
            time.sleep(5)
        finally:
            if "proc" in locals() and proc.poll() is None:
                proc.terminate()


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Uruchom skrypt z uprawnieniami root (sudo)!")
        sys.exit(1)
    main_loop()