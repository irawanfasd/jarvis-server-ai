#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
J.A.R.V.I.S. v2.1 - Asisten admin server lokal (Ollama), dioptimalkan untuk STB RAM kecil.

Cara kerja: ROUTER kata kunci (instan) -> LLM (JSON ringkas) -> SAFETY -> eksekusi -> self-fix.
Env: JARVIS_MODEL, JARVIS_BASE, JARVIS_KEEP (default 5m), JARVIS_THREADS, JARVIS_MINMB (default 600)
"""
import datetime
import json
import os
import re
import shlex
import subprocess
import threading
import time
import urllib.error
import urllib.request

try:
    import readline  # noqa: F401
except ImportError:
    pass

BASE_URL = os.environ.get("JARVIS_BASE", "http://127.0.0.1:11434")
MODEL = os.environ.get("JARVIS_MODEL", "qwen2.5:0.5b")
KEEP_DEFAULT = os.environ.get("JARVIS_KEEP", "5m")
KEEP = KEEP_DEFAULT
NUM_CTX = 1024          # JANGAN diubah-ubah: beda nilai = model dimuat ulang
NUM_THREAD = int(os.environ.get("JARVIS_THREADS", os.cpu_count() or 4))
MIN_FREE_MB = int(os.environ.get("JARVIS_MINMB", "600"))
LOG_FILE = "/var/log/jarvis.log"
MAX_FIX = 2
HISTORY_TURNS = 4
IS_ROOT = (os.geteuid() == 0)
SUMMARIZE = False
SHOW_STATS = True


def c(code, text):
    return f"\033[{code}m{text}\033[0m"


# ======================================================================
# TOOLS: (deskripsi, perintah, butuh_nama_layanan, risiko)
# ======================================================================
TOOLS = {
    "ram":           ("Pemakaian RAM & swap", "free -h", False, "safe"),
    "disk":          ("Pemakaian disk", "df -h -x tmpfs -x devtmpfs", False, "safe"),
    "suhu":          ("Suhu CPU", r"""cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | awk '{printf "%.1f C\n", $1/1000}'""", False, "safe"),
    "cpu":           ("Beban CPU & uptime", "uptime; echo; ps -eo pid,comm,%cpu --sort=-%cpu | head -6", False, "safe"),
    "proses":        ("Proses paling boros RAM", "ps -eo pid,user,comm,%mem,rss --sort=-rss | head -11", False, "safe"),
    "port":          ("Port yang listen", "ss -tulpn", False, "safe"),
    "jaringan":      ("IP & rute", "ip -br addr; echo; ip route | head -5", False, "safe"),
    "layanan_aktif": ("Layanan berjalan", "systemctl list-units --type=service --state=running --no-pager --plain", False, "safe"),
    "layanan_gagal": ("Layanan gagal", "systemctl --failed --no-pager --plain", False, "safe"),
    "status":        ("Status layanan", "systemctl status {arg} --no-pager -l | head -25", True, "safe"),
    "log":           ("Log layanan", "journalctl -u {arg} -n 40 --no-pager", True, "safe"),
    "restart":       ("Restart layanan", "systemctl restart {arg} && systemctl is-active {arg}", True, "confirm"),
    "nginx_test":    ("Tes konfigurasi nginx", "nginx -t", False, "safe"),
    "bersihkan_ram": ("Bersihkan cache RAM", "/usr/local/bin/clean-ram", False, "confirm"),
    "login":         ("Siapa yang login", "who; echo; last -n 5 2>/dev/null", False, "safe"),
    "web":           ("Isi /var/www", "ls -la /var/www", False, "safe"),
    "besar":         ("Folder terbesar di /var/www", "du -h --max-depth=1 /var/www 2>/dev/null | sort -rh | head -10", False, "safe"),
    "swap":          ("Info swap", "swapon --show; echo; free -h", False, "safe"),
    "ollama":        ("Status model Ollama", "ollama ps; echo; journalctl -u ollama -n 5 --no-pager", False, "safe"),
    "ringkasan":     ("Ringkasan kondisi server", r"""echo "== Uptime =="; uptime; echo "== RAM =="; free -h | head -2; echo "== Disk / =="; df -h / | tail -1; echo "== Suhu =="; cat /sys/class/thermal/thermal_zone*/temp 2>/dev/null | awk '{printf "%.1f C\n", $1/1000}'; echo "== Layanan gagal =="; systemctl --failed --no-legend --plain | head -5; echo "(selesai)" """, False, "safe"),
}

RULES = [
(r"\b(cek|lihat|status|tampilkan)\b.*\b(servis|service|layanan)\b", "layanan_aktif", None),
    (r"\b(bersihkan|hapus)\b.*\b(ram|cache)\b", "bersihkan_ram", None),  
  (r"\b(bersihkan|hapus)\b.*\b(ram|cache)\b", "bersihkan_ram", None),
    (r"\b(ringkasan|dashboard|kondisi|kesehatan)\b|\b(status|cek)\s+(server|stb|sistem)\b", "ringkasan", None),
    (r"\brestart\s+([\w.@-]+)", "restart", 1),
    (r"\bstatus\s+([\w.@-]+)", "status", 1),
    (r"\b(log|journal)\s+([\w.@-]+)", "log", 2),
    (r"\bnginx\b.*\b(test|tes)\b", "nginx_test", None),
    (r"\bswap\b", "swap", None),
    (r"\b(ram|memori|memory)\b", "ram", None),
    (r"\b(disk|storage|penyimpanan|sdcard)\b", "disk", None),
    (r"\b(suhu|temperatur|temperature)\b", "suhu", None),
    (r"\b(cpu|beban|load|uptime)\b", "cpu", None),
    (r"\b(port|listening)\b", "port", None),
    (r"\b(proses|process)\b", "proses", None),
    (r"\b(gagal|failed)\b", "layanan_gagal", None),
    (r"\b(layanan|service)\b.*\b(aktif|jalan|running)\b", "layanan_aktif", None),
    (r"\b(ip|jaringan|network)\b", "jaringan", None),
    (r"\b(siapa|yang)\b.*\blogin\b|\bwho\b", "login", None),
    (r"\b(terbesar|paling besar)\b", "besar", None),
    (r"\b(website|web|situs)\b.*\b(apa|daftar|list)\b|\bisi\s+/?var/www\b", "web", None),
    (r"\bollama\b", "ollama", None),
    (r"^cek\s+([\w.@-]+)$", "status", 1),
]

SMALLTALK = [
    (r"\b(siapa kamu|kamu siapa|siapa anda|kenalkan)\b",
     "Saya JARVIS, asisten admin server milik Bos Irawan. Ketik /tools untuk melihat kemampuan saya."),
    (r"\b(terima kasih|makasih|thanks|thx)\b", "Siap, Bos!"),
    (r"\b(bantuan|help|bisa apa)\b",
     "Saya bisa cek ram/disk/suhu/cpu, status/restart/log layanan, port, proses, ringkasan server, dan perintah bebas lewat AI. Ketik /tools."),
]

# ======================================================================
# SAFETY
# ======================================================================
BLOCK = [
    r"\brm\s+(-\S+\s+)*(/|/\*|~|~/|\*|/etc|/usr|/var|/boot|/home|/bin|/sbin|/lib|/opt)(\s|$)",
    r"\bmkfs", r"\bwipefs\b", r"\b(fdisk|sfdisk|cfdisk|parted)\b",
    r"\bdd\b.*\bof=/dev/", r">\s*/dev/(sd|mmc|nvme|zram)",
    r":\(\)\s*\{",
    r"\bchmod\s+-R\s+\S+\s+/(\s|$)", r"\bchown\s+-R\s+\S+\s+/(\s|$)",
    r"(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba)?sh\b",
]
INTERACTIVE_PROGS = {"nano", "vi", "vim", "top", "htop", "less", "more", "man", "watch", "mc"}
INTERACTIVE = [r"\btail\s+(-\w*f|--follow)", r"\bjournalctl\b.*\s-\w*f"]
DANGER = [
    r"\b(reboot|shutdown|poweroff|halt)\b", r"\binit\s+[06]\b",
    r"\brm\b",
    r"\b(apt|apt-get)\s+(remove|purge|autoremove)",
    r"\bsystemctl\s+(stop|disable|mask)\s+(ssh|sshd|networking|NetworkManager)",
    r"\b(iptables|nft|ufw)\b",
    r"\b(userdel|deluser|passwd|usermod)\b",
]
SENSITIVE = [r"/etc/(shadow|sudoers)", r"id_(rsa|ed25519|ecdsa)", r"\.env\b"]
READONLY = {
    "ls", "cat", "head", "tail", "grep", "egrep", "wc", "sort", "uniq", "cut", "awk",
    "df", "du", "free", "uptime", "ps", "pgrep", "ss", "netstat", "ip", "who", "w",
    "whoami", "id", "hostname", "uname", "date", "lsblk", "lsusb", "lscpu", "lsmod",
    "dmesg", "journalctl", "systemctl", "stat", "file", "pwd", "echo", "which",
    "dpkg", "apt-cache", "find", "sensors", "last", "swapon",
}
SYSTEMCTL_OK = {"status", "is-active", "is-enabled", "list-units", "list-unit-files",
                "show", "cat", "list-timers", "--failed"}
META = [";", "&&", "||", ">", "<", "`", "$(", "\n", "&"]


def is_interactive(cmd):
    for seg in re.split(r"[|;&]+", cmd):
        try:
            tok = shlex.split(seg)
        except ValueError:
            continue
        while tok and tok[0] == "sudo":
            tok = tok[1:]
        if tok and os.path.basename(tok[0]) in INTERACTIVE_PROGS:
            return True
    return any(re.search(p, cmd) for p in INTERACTIVE)


def is_readonly(cmd):
    if any(m in cmd for m in META) or any(re.search(p, cmd) for p in SENSITIVE):
        return False
    for seg in cmd.split("|"):
        try:
            tok = shlex.split(seg)
        except ValueError:
            return False
        while tok and tok[0] == "sudo":
            tok = tok[1:]
        if not tok or os.path.basename(tok[0]) not in READONLY:
            return False
        name = os.path.basename(tok[0])
        if name == "systemctl" and not (set(tok[1:]) & SYSTEMCTL_OK):
            return False
        if name == "ip" and set(tok[1:]) & {"add", "del", "delete", "set", "flush", "replace"}:
            return False
        if name == "find" and set(tok[1:]) & {"-delete", "-exec", "-execdir", "-ok"}:
            return False
        if name == "awk" and "system(" in seg:
            return False
    return True


def classify(cmd):
    flat = re.sub(r"\s+", " ", cmd)
    if any(re.search(p, flat) for p in BLOCK):
        return "block"
    if is_interactive(cmd):
        return "interactive"
    if any(re.search(p, flat) for p in DANGER):
        return "danger"
    if is_readonly(cmd):
        return "safe"
    return "confirm"


def gate(level):
    if level == "block":
        print(c("1;31", "⛔ Diblokir demi keamanan: perintah ini bisa merusak sistem."))
        return False
    if level == "interactive":
        print(c("1;31", "⛔ Perintah interaktif tidak didukung (nano/top/less/tail -f, dll)."))
        return False
    if level == "safe":
        return True
    if level == "confirm":
        return input(c("1;33", "❓ Perintah ini mengubah sistem. Jalankan? [y/N] ")).strip().lower() in ("y", "ya")
    if level == "danger":
        return input(c("1;31", "⚠️  BERBAHAYA. Ketik YAKIN untuk melanjutkan: ")).strip() == "YAKIN"
    return False


# ======================================================================
# SHELL & SISTEM
# ======================================================================
def run_shell(cmd, timeout=60):
    argv = ["bash", "-c", cmd] if IS_ROOT else ["sudo", "-n", "bash", "-c", cmd]
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive", LANG="C.UTF-8")
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL, env=env)
        return p.returncode, (p.stdout + p.stderr).strip()[-3000:]
    except subprocess.TimeoutExpired:
        return 124, f"Timeout setelah {timeout} detik."
    except Exception as e:  # noqa: BLE001
        return 1, f"Gagal menjalankan: {e}"


def sh_quiet(cmd, timeout=5):
    try:
        return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True,
                              timeout=timeout).stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def audit(kind, text):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S} [{kind}] {text}\n")
    except OSError:
        pass


def mem_available_mb():
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) // 1024
    except OSError:
        pass
    return 99999


_svc_cache = (0, set())
_ctx_cache = (0, "")


def known_services():
    global _svc_cache
    if time.time() - _svc_cache[0] > 120:
        out = sh_quiet("systemctl list-unit-files --type=service --no-legend --plain | awk '{print $1}'")
        _svc_cache = (time.time(), {s.replace(".service", "") for s in out.splitlines() if s})
    return _svc_cache[1]


def live_context():
    """Konteks STABIL (tanpa angka yang berubah-ubah) agar cache prompt Ollama tetap terpakai."""
    global _ctx_cache
    if time.time() - _ctx_cache[0] < 600:
        return _ctx_cache[1]
    svc = sh_quiet(r"""systemctl list-units --type=service --state=running --no-legend --plain | awk '{print $1}' | sed 's/\.service$//' | grep -vE '^(systemd|dbus|getty|serial|user|rsyslog|cron|armbian|polkit|udisks|avahi|wpa|ModemManager|networkd|unattended|haveged)' | head -15 | tr '\n' ' '""")
    web = sh_quiet(r"""ls /var/www 2>/dev/null | head -10 | tr '\n' ' '""")
    _ctx_cache = (time.time(), f"Layanan: {svc}\n/var/www: {web}")
    return _ctx_cache[1]


# ======================================================================
# LLM (Ollama)
# ======================================================================
SCHEMA = {
    "type": "object",
    "properties": {"a": {"type": "string", "enum": ["t", "b", "j"]}, "x": {"type": "string"}},
    "required": ["a", "x"],
}


def build_system_prompt():
    names = " ".join(n + (" <svc>" if t[2] else "") for n, t in TOOLS.items())
    return f"""Kamu JARVIS, admin server Linux Armbian milik Bos Irawan (sudah root, tanpa sudo). Balas HANYA JSON {{"a":..,"x":..}}.
a="t": gunakan Tool bawaan (jika sangat cocok). x="nama_tool [arg]".
a="b": tulis perintah bash BEBAS (jika Tool tidak cocok). x="perintah_bash".
a="j": jawab pertanyaan singkat. x="jawaban".

ATURAN BASH BEBAS:
- Jika user minta "bersihkan sistem", gunakan: apt clean && apt autoremove -y && journalctl --vacuum-size=50M
- Jika user minta "buat file/folder", gunakan: mkdir, echo, atau touch.
- JANGAN gunakan perintah interaktif (nano, vi, top).
- JANGAN pakai sudo (kamu sudah root).

Tool: {names}
{live_context()}
Contoh:
"jalankan pembersihan" => {{"a":"b","x":"apt clean && apt autoremove -y && journalctl --vacuum-size=50M"}}
"buat folder proyek" => {{"a":"b","x":"mkdir -p /var/www/proyek"}}
"cek nginx" => {{"a":"t","x":"status nginx"}}
"apa itu nginx" => {{"a":"j","x":"Nginx adalah web server."}}"""

def http_json(path, payload=None, timeout=5):
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(BASE_URL + path, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def loaded_models():
    """Daftar model yang sedang di RAM; None bila Ollama tidak merespons."""
    try:
        return [m.get("name", "") for m in http_json("/api/ps").get("models", [])]
    except Exception:  # noqa: BLE001
        return None


def model_is_loaded(names):
    return MODEL in names or (MODEL + ":latest") in names


def options(num_predict):
    return {"temperature": 0, "num_predict": num_predict, "num_ctx": NUM_CTX, "num_thread": NUM_THREAD}


def show_stats(d, wall):
    if not SHOW_STATS or not d.get("eval_count"):
        return
    load = d.get("load_duration", 0) / 1e9
    pe, ped = d.get("prompt_eval_count", 0), d.get("prompt_eval_duration", 0) / 1e9
    ec, ed = d.get("eval_count", 0), d.get("eval_duration", 0) / 1e9
    tps = (ec / ed) if ed else 0
    print(c("1;90", f"⏱  total {wall:.1f}s | muat {load:.1f}s | prompt {pe} tok {ped:.1f}s | output {ec} tok ({tps:.1f} tok/s)"))


def _stream(payload, quiet):
    req = urllib.request.Request(BASE_URL + "/api/chat", data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"})
    t0, parts, counter, stats = time.time(), [], [0], {}
    stop = threading.Event()

    def ticker():
        while not stop.wait(1):
            print(f"\r\033[1;90m⏳ berpikir... {time.time() - t0:3.0f}s ({counter[0]} token)\033[0m", end="", flush=True)

    if not quiet:
        threading.Thread(target=ticker, daemon=True).start()
    try:
        with urllib.request.urlopen(req, timeout=900) as r:
            for line in r:
                if not line.strip():
                    continue
                d = json.loads(line)
                if "error" in d:
                    raise RuntimeError(d["error"])
                piece = d.get("message", {}).get("content", "")
                if piece:
                    parts.append(piece)
                    counter[0] += 1
                if d.get("done"):
                    stats = d
    finally:
        stop.set()
        if not quiet:
            print("\r" + " " * 48 + "\r", end="", flush=True)
    if not quiet:
        show_stats(stats, time.time() - t0)
    return "".join(parts).strip()


def llm(messages, fmt=SCHEMA, num_predict=100, quiet=False):
    payload = {"model": MODEL, "messages": messages, "stream": True,
               "keep_alive": KEEP, "options": options(num_predict)}
    if fmt:
        payload["format"] = fmt
    try:
        return _stream(payload, quiet)
    except urllib.error.HTTPError as e:
        if e.code == 400 and fmt:       # Ollama lama tanpa JSON schema
            payload["format"] = "json"
            return _stream(payload, quiet)
        raise


def prime():
    """Muat model + hangatkan cache prompt di latar belakang (prefix prompt sama dengan request nyata)."""
    def work():
        try:
            llm([{"role": "system", "content": build_system_prompt()},
                 {"role": "user", "content": "ping"}], num_predict=1, quiet=True)
        except Exception:  # noqa: BLE001
            pass
    threading.Thread(target=work, daemon=True).start()


def unload():
    try:
        http_json("/api/generate", {"model": MODEL, "keep_alive": 0, "stream": False}, timeout=15)
    except Exception:  # noqa: BLE001
        pass


def ensure_ram_ok():
    names = loaded_models()
    if names is None:
        print(c("1;31", "Ollama tidak merespons. Cek: systemctl status ollama"))
        return False
    if model_is_loaded(names):
        return True
    avail = mem_available_mb()
    if avail >= MIN_FREE_MB:
        return True
    print(c("1;33", f"⚠️  RAM tersedia hanya {avail} MB (butuh ≥{MIN_FREE_MB} MB). Model akan lambat / swap."))
    print(c("1;90", "   Saran: 'bersihkan ram', cek 'proses' paling boros, atau /model qwen2.5:0.5b"))
    return input(c("1;33", "   Tetap lanjut? [y/N] ")).strip().lower() in ("y", "ya")


def normalize(d):
    if not isinstance(d, dict):
        return {"action": "jawab", "jawaban": str(d)}
    if "action" in d:
        return d
    a, x = d.get("a"), str(d.get("x", "")).strip()
    if a == "t":
        p = x.split(None, 1)
        return {"action": "tool", "tool": p[0] if p else "", "arg": p[1].strip() if len(p) > 1 else "", "_raw": d}
    if a == "b":
        return {"action": "bash", "command": x, "_raw": d}
    return {"action": "jawab", "jawaban": x or "(tidak paham)", "_raw": d}


def parse_plan(txt):
    try:
        return normalize(json.loads(txt))
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", txt, re.S)
        if m:
            try:
                return normalize(json.loads(m.group(0)))
            except json.JSONDecodeError:
                pass
    return {"action": "jawab", "jawaban": txt}


def ask_plan(messages):
    try:
        return parse_plan(llm(messages))
    except Exception as e:  # noqa: BLE001
        print(c("1;31", f"Error menghubungi Ollama: {e}"))
        return None


# ======================================================================
# LOGIKA UTAMA
# ======================================================================
history = []


def remember(role, text):
    history.append({"role": role, "content": text[:160]})
    del history[:-HISTORY_TURNS]


def build_tool_cmd(name, arg):
    t = TOOLS.get(name or "")
    if not t:
        return None, None, f"Tool '{name}' tidak dikenal."
    cmd = t[1]
    if t[2]:
        arg = (arg or "").strip().replace(".service", "")
        if not re.fullmatch(r"[A-Za-z0-9_.@-]+", arg):
            return None, None, "Nama layanan tidak valid."
        if arg not in known_services():
            return None, None, f"Layanan '{arg}' tidak ditemukan di server ini."
        cmd = cmd.format(arg=arg)
    return cmd, t[3], None


def clean_cmd(text):
    cmd = (text or "").replace("```bash", "").replace("```sh", "").replace("```", "").strip()
    if IS_ROOT and "sudo -" not in cmd:
        cmd = re.sub(r"\bsudo\s+", "", cmd)
    return cmd


def route(text):
    low = text.lower().strip()
    if re.match(r"^(halo|hai|hi|hello|selamat\s+\w+|p)\b", low) and len(low.split()) <= 3:
        return {"action": "jawab", "jawaban": "Halo Bos Irawan! Sistem siap menerima perintah."}
    for pat, ans in SMALLTALK:
        if re.search(pat, low):
            return {"action": "jawab", "jawaban": ans}
    if len(low.split()) > 6:
        return None
    for pat, tool, grp in RULES:
        m = re.search(pat, low)
        if not m:
            continue
        arg = m.group(grp) if grp else ""
        if TOOLS[tool][2] and arg.replace(".service", "") not in known_services():
            continue
        return {"action": "tool", "tool": tool, "arg": arg}
    return None


def summarize(cmd, out):
    try:
        msgs = [{"role": "system", "content": "Ringkas output server dalam 1-3 kalimat bahasa Indonesia. Sebutkan masalah jika ada."},
                {"role": "user", "content": f"Perintah: {cmd}\nOutput:\n{out[-1200:]}"}]
        print(c("1;32", "🤖 ") + llm(msgs, fmt=None, num_predict=120))
    except Exception:  # noqa: BLE001
        pass


def process_plan(plan, user_input, messages):
    for attempt in range(MAX_FIX + 1):
        action = plan.get("action")

        if action == "jawab":
            ans = plan.get("jawaban") or "(tidak ada jawaban)"
            print("\n" + c("1;32", "🤖 ") + ans)
            remember("user", user_input)
            remember("assistant", ans)
            return

        cmd, level, err = None, None, None
        if action == "tool":
            cmd, level, err = build_tool_cmd(plan.get("tool"), plan.get("arg", ""))
            
            # JIKA TOOL TIDAK DITEMUKAN, ANGGAP SEBAGAI PERINTAH BASH BEBAS
            if err and "tidak dikenal" in err:
                print(c("1;33", f"⚠️  Tool '{plan.get('tool')}' tidak ada. Mencoba sebagai perintah bash bebas..."))
                cmd = f"{plan.get('tool')} {plan.get('arg', '')}".strip()
                level = classify(cmd)
                err = None # Hapus error
        elif action == "bash":
            cmd = clean_cmd(plan.get("command"))
            if not cmd:
                err = "Perintah kosong."
            else:
                level = classify(cmd)
        else:
            err = "Format rencana tidak valid."
        rc, out = 1, err
        if not err:
            print(f"\n{c('1;34', '💻 Perintah:')} {c('1;97', cmd)}  {c('1;90', f'[{level}]')}")
            if not gate(level):
                audit("DITOLAK", f"{level}: {cmd}")
                return
            print(c("1;90", "⚙️  Menjalankan..."))
            timeout = 300 if re.search(r"\b(apt|apt-get|pip3?|git|npm)\b", cmd) else 60
            rc, out = run_shell(cmd, timeout)
            audit("JALAN", f"rc={rc} {cmd}")
            print(c("1;90", "--- Output ---"))
            print(out if out else "(Berhasil, tanpa output)")
            print(c("1;90", "--------------"))
        else:
            print(c("1;31", f"⚠️  {err}"))

        if rc == 0:
            remember("user", user_input)
            remember("assistant", f"Menjalankan: {cmd}")
            if SUMMARIZE and out:
                summarize(cmd, out)
            return

        if attempt == MAX_FIX:
            print(c("1;31", "Gagal setelah beberapa percobaan perbaikan."))
            return
        print(c("1;33", f"🔁 Gagal (kode {rc}). Meminta AI memperbaiki ({attempt + 1}/{MAX_FIX})..."))
        messages.append({"role": "assistant", "content": json.dumps(plan.get("_raw", plan), ensure_ascii=False)})
        messages.append({"role": "user", "content":
                         f"Gagal (exit {rc}): {(out or '')[-400:]}\nBerikan perintah perbaikan, atau a=j berisi penjelasan."})
        plan = ask_plan(messages)
        if plan is None:
            return


def handle(user_input):
    global MODEL, SUMMARIZE, KEEP, SHOW_STATS
    low = user_input.strip().lower()

    if low == "/help":
        print("Perintah: /model <nama>  /hemat  /ringkas  /stat  /lupa  /log  /tools  exit")
        print("Contoh  : ringkasan | cek ram | status nginx | restart php8.2-fpm | log ssh | file terbesar di /var/www")
        return
    if low == "/tools":
        for n, d in TOOLS.items():
            print(f"  {n:14} {d[0]}")
        return
    if low.startswith("/model"):
        parts = user_input.split()
        if len(parts) > 1:
            unload()
            MODEL = parts[1]
            print(f"Model diganti ke: {MODEL} (akan dimuat saat dipakai)")
        else:
            print(f"Model aktif: {MODEL}")
        return
    if low == "/hemat":
        if KEEP != "0":
            KEEP = "0"
            unload()
            print("Mode HEMAT RAM: model dibuang dari RAM setelah tiap jawaban (jawaban pertama lebih lambat).")
        else:
            KEEP = KEEP_DEFAULT
            print(f"Mode normal: model dipertahankan di RAM selama {KEEP}.")
        return
    if low == "/ringkas":
        SUMMARIZE = not SUMMARIZE
        print(f"Ringkasan AI: {'ON' if SUMMARIZE else 'OFF'}")
        return
    if low == "/stat":
        SHOW_STATS = not SHOW_STATS
        print(f"Statistik kecepatan: {'ON' if SHOW_STATS else 'OFF'}")
        return
    if low == "/lupa":
        history.clear()
        print("Riwayat percakapan dihapus.")
        return
    if low == "/log":
        os.system(f"tail -n 20 {LOG_FILE}")
        return

    plan = route(user_input)
    if plan is None:
        if not ensure_ram_ok():
            return
        messages = [{"role": "system", "content": build_system_prompt()}] + history + \
                   [{"role": "user", "content": user_input}]
        plan = ask_plan(messages)
        if plan is None:
            return
    else:
        messages = [{"role": "system", "content": build_system_prompt()}] + history + \
                   [{"role": "user", "content": user_input}]
    process_plan(plan, user_input, messages)


def main():
    names = loaded_models()
    avail = mem_available_mb()
    print(c("1;36", "================================================"))
    print("🤖 " + c("1;32", "J.A.R.V.I.S. v2.1") + c("1;90", f"  model: {MODEL}  | RAM tersedia: {avail} MB"))
    print("Ketik /help untuk bantuan, 'exit' untuk keluar.")
    if names is None:
        print(c("1;31", "Ollama belum aktif; hanya perintah bawaan (router) yang jalan."))
    elif model_is_loaded(names):
        print(c("1;90", "Model sudah di RAM."))
    elif avail >= MIN_FREE_MB:
        print(c("1;90", "Memanaskan model di latar belakang..."))
        prime()
    else:
        print(c("1;33", f"RAM tersedia {avail} MB < {MIN_FREE_MB} MB: model tidak dimuat otomatis."))
    print(c("1;36", "================================================"))
    while True:
        try:
            user_input = input("\n" + c("1;33", "Bos > ")).strip()
            if user_input.lower() in ("exit", "quit", "keluar"):
                print("Sampai jumpa, Bos!")
                break
            if not user_input:
                continue
            handle(user_input)
        except KeyboardInterrupt:
            print("\nDibatalkan. Keluar...")
            break
        except EOFError:
            break
        except Exception as e:  # noqa: BLE001
            print(c("1;31", f"Error: {e}"))


if __name__ == "__main__":
    main()
