#!/usr/bin/env python3
"""
SecureBot AI Guardian - Mini-SOC Monitor
Ueberwacht System, Bot, DB, SSH und sendet Alerts via Telegram.

Ein Produkt von Frieguen fuer Lee.
"""

import os
import re
import json
import time
import gzip
import shutil
import sqlite3
import hashlib
import asyncio
import logging
import http.client
import socket
from datetime import datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv
from telegram import Bot

load_dotenv()

# Logging
logging.basicConfig(
    format='%(asctime)s - guardian - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger('guardian')


# ============================================================
# GuardianConfig
# ============================================================
class GuardianConfig:
    TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
    ADMIN_USER_ID = int(os.getenv("ADMIN_USER_ID", "0"))
    DB_PATH = '/app/data/securebot.db'
    BOT_CONTAINER = 'securebot-ai'
    BACKUP_DIR = '/app/backups'
    STATUS_FILE = '/app/data/guardian_status.json'
    CHECK_INTERVAL = 300  # 5 Minuten
    BACKUP_HOUR = 3       # 03:00 UTC
    REPORT_HOUR = 7       # 07:00 UTC (08:00 CET)
    BACKUP_RETENTION_DAYS = 30
    # Schwellwerte
    CPU_WARN = 85.0
    RAM_WARN = 85.0
    RAM_CRIT = 95.0
    DISK_WARN = 80.0
    DISK_CRIT = 90.0
    DB_MAX_SIZE_MB = 100
    DB_GROWTH_WARN = 0.20  # 20%
    SSH_FAIL_WARN_PER_IP = 10
    SSH_FAIL_CRIT_TOTAL = 50
    # Pfade (im Container gemountet)
    PROC_PATH = '/host/proc'
    LOG_PATH = '/host/log'


# ============================================================
# AlertManager - Telegram Alerts mit Deduplication
# ============================================================
class AlertManager:
    def __init__(self, token: str, admin_id: int):
        self.bot = Bot(token=token)
        self.admin_id = admin_id
        self.history: dict[str, float] = {}
        self.cooldown = 3600  # 60 Min Dedup
        self.alerts_today = 0
        self.last_reset = datetime.now().date()

    async def send(self, severity: str, title: str, msg: str, key: str = None):
        # Tages-Reset
        today = datetime.now().date()
        if today != self.last_reset:
            self.alerts_today = 0
            self.last_reset = today

        # Deduplication
        if key:
            last = self.history.get(key, 0)
            if time.time() - last < self.cooldown:
                return
            self.history[key] = time.time()

        emoji = {"CRITICAL": "\U0001f6a8", "WARNING": "\u26a0\ufe0f", "INFO": "\u2139\ufe0f"}.get(severity, "\u2139\ufe0f")
        text = f"{emoji} **[{severity}] {title}**\n\n{msg}\n\n_Guardian | {datetime.now().strftime('%H:%M:%S')}_"

        try:
            await self.bot.send_message(
                chat_id=self.admin_id,
                text=text,
                parse_mode='Markdown'
            )
            self.alerts_today += 1
            logger.info(f"Alert gesendet: [{severity}] {title}")
        except Exception as e:
            logger.error(f"Alert senden fehlgeschlagen: {e}")

    async def send_report(self, text: str):
        try:
            await self.bot.send_message(
                chat_id=self.admin_id,
                text=text,
                parse_mode='Markdown'
            )
        except Exception as e:
            logger.error(f"Report senden fehlgeschlagen: {e}")


# ============================================================
# SystemMonitor - CPU/RAM/Disk via /proc
# ============================================================
class SystemMonitor:
    def __init__(self, proc_path: str):
        self.proc = proc_path
        self._prev_cpu = None

    def get_cpu(self) -> float:
        try:
            with open(f'{self.proc}/stat') as f:
                parts = f.readline().split()
            vals = [int(x) for x in parts[1:8]]
            idle = vals[3]
            total = sum(vals)

            if self._prev_cpu is None:
                self._prev_cpu = (idle, total)
                return 0.0

            prev_idle, prev_total = self._prev_cpu
            self._prev_cpu = (idle, total)

            d_idle = idle - prev_idle
            d_total = total - prev_total
            if d_total == 0:
                return 0.0
            return round((1.0 - d_idle / d_total) * 100, 1)
        except Exception:
            return -1.0

    def get_memory(self) -> dict:
        try:
            info = {}
            with open(f'{self.proc}/meminfo') as f:
                for line in f:
                    parts = line.split()
                    if parts[0] in ('MemTotal:', 'MemAvailable:'):
                        info[parts[0].rstrip(':')] = int(parts[1])
            total = info.get('MemTotal', 0) // 1024
            avail = info.get('MemAvailable', 0) // 1024
            used = total - avail
            pct = round(used / total * 100, 1) if total > 0 else 0
            return {'total_mb': total, 'used_mb': used, 'avail_mb': avail, 'percent': pct}
        except Exception:
            return {'total_mb': 0, 'used_mb': 0, 'avail_mb': 0, 'percent': -1}

    def get_disk(self) -> dict:
        try:
            st = os.statvfs('/')
            total = st.f_blocks * st.f_frsize
            free = st.f_bavail * st.f_frsize
            used = total - free
            total_gb = round(total / (1024**3), 1)
            used_gb = round(used / (1024**3), 1)
            pct = round(used / total * 100, 1) if total > 0 else 0
            return {'total_gb': total_gb, 'used_gb': used_gb, 'percent': pct}
        except Exception:
            return {'total_gb': 0, 'used_gb': 0, 'percent': -1}

    def get_load(self) -> str:
        try:
            with open(f'{self.proc}/loadavg') as f:
                parts = f.read().split()
            return f"{parts[0]}, {parts[1]}, {parts[2]}"
        except Exception:
            return "?"


# ============================================================
# DockerMonitor - Container-Status via Docker Socket
# ============================================================
class DockerMonitor:
    SOCKET = '/var/run/docker.sock'

    def _request(self, path: str) -> dict:
        try:
            conn = http.client.HTTPConnection('localhost')
            conn.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            conn.sock.connect(self.SOCKET)
            conn.request('GET', path)
            resp = conn.getresponse()
            data = json.loads(resp.read().decode())
            conn.close()
            return data
        except Exception as e:
            logger.warning(f"Docker Socket Fehler: {e}")
            return {}

    def get_status(self, name: str) -> dict:
        data = self._request(f'/containers/{name}/json')
        if not data:
            return {'running': False, 'status': 'unknown', 'restarts': 0}
        state = data.get('State', {})
        restarts = data.get('RestartCount', 0)
        return {
            'running': state.get('Running', False),
            'status': state.get('Status', 'unknown'),
            'restarts': restarts,
            'started': state.get('StartedAt', '?')[:19]
        }


# ============================================================
# DatabaseMonitor - SQLite Integrity + Size
# ============================================================
class DatabaseMonitor:
    def check_integrity(self, path: str) -> tuple:
        try:
            conn = sqlite3.connect(path, timeout=5)
            conn.execute('PRAGMA query_only = ON')
            result = conn.execute('PRAGMA integrity_check').fetchone()[0]
            conn.close()
            return (result == 'ok', result)
        except Exception as e:
            return (False, str(e))

    def get_size_kb(self, path: str) -> int:
        try:
            return os.path.getsize(path) // 1024
        except Exception:
            return -1

    def get_user_count(self, path: str) -> int:
        try:
            conn = sqlite3.connect(path, timeout=5)
            conn.execute('PRAGMA query_only = ON')
            count = conn.execute('SELECT count(*) FROM users').fetchone()[0]
            conn.close()
            return count
        except Exception:
            return -1

    def get_today_queries(self, path: str) -> int:
        try:
            conn = sqlite3.connect(path, timeout=5)
            conn.execute('PRAGMA query_only = ON')
            today = datetime.now().strftime('%Y-%m-%d')
            count = conn.execute(
                'SELECT COALESCE(SUM(count), 0) FROM daily_usage WHERE date = ?',
                (today,)
            ).fetchone()[0]
            conn.close()
            return count
        except Exception:
            return -1


# ============================================================
# FileIntegrityMonitor - SHA256 Hashes
# ============================================================
class FileIntegrityMonitor:
    WATCHED = ['/app/bot.py', '/app/requirements.txt']

    def __init__(self):
        self.baseline: dict[str, str] = {}

    def _hash(self, path: str) -> str:
        try:
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ''

    def create_baseline(self):
        for path in self.WATCHED:
            h = self._hash(path)
            if h:
                self.baseline[path] = h
                logger.info(f"FIM Baseline: {path} = {h[:16]}...")

    def check(self) -> list:
        changed = []
        for path, expected in self.baseline.items():
            current = self._hash(path)
            if current and current != expected:
                changed.append(path)
        return changed


# ============================================================
# SSHMonitor - Failed Login Detection
# ============================================================
class SSHMonitor:
    def __init__(self, log_path: str):
        self.auth_log = f'{log_path}/auth.log'
        self.last_pos = 0
        self.failed_ips: dict[str, int] = {}
        self.total_failed = 0

    def check(self) -> dict:
        try:
            if not os.path.exists(self.auth_log):
                return {'total': 0, 'ips': {}}

            size = os.path.getsize(self.auth_log)
            if size < self.last_pos:
                self.last_pos = 0  # Log rotiert

            with open(self.auth_log, 'r', errors='ignore') as f:
                f.seek(self.last_pos)
                new_lines = f.readlines()
                self.last_pos = f.tell()

            pattern = re.compile(r'Failed password.*from (\d+\.\d+\.\d+\.\d+)')
            for line in new_lines:
                m = pattern.search(line)
                if m:
                    ip = m.group(1)
                    self.failed_ips[ip] = self.failed_ips.get(ip, 0) + 1
                    self.total_failed += 1

            return {'total': self.total_failed, 'ips': dict(self.failed_ips)}
        except Exception:
            return {'total': 0, 'ips': {}}

    def reset_daily(self):
        self.failed_ips.clear()
        self.total_failed = 0


# ============================================================
# BackupManager - SQLite Backup + Rotation
# ============================================================
class BackupManager:
    def __init__(self, backup_dir: str, retention: int):
        self.dir = backup_dir
        self.retention = retention
        Path(self.dir).mkdir(parents=True, exist_ok=True)

    def create(self, db_path: str) -> tuple:
        try:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = f'{self.dir}/securebot_{ts}.db'
            gz_path = f'{backup_path}.gz'

            # SQLite .backup() API - konsistenter Snapshot
            src = sqlite3.connect(db_path)
            dst = sqlite3.connect(backup_path)
            src.backup(dst)
            dst.close()
            src.close()

            # Komprimieren
            with open(backup_path, 'rb') as f_in:
                with gzip.open(gz_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            os.remove(backup_path)

            size_kb = os.path.getsize(gz_path) // 1024
            logger.info(f"Backup erstellt: {gz_path} ({size_kb} KB)")
            return (True, gz_path)
        except Exception as e:
            logger.error(f"Backup fehlgeschlagen: {e}")
            return (False, str(e))

    def rotate(self):
        cutoff = datetime.now() - timedelta(days=self.retention)
        try:
            for f in Path(self.dir).glob('securebot_*.db.gz'):
                if datetime.fromtimestamp(f.stat().st_mtime) < cutoff:
                    f.unlink()
                    logger.info(f"Altes Backup geloescht: {f.name}")
        except Exception as e:
            logger.error(f"Backup-Rotation Fehler: {e}")

    def info(self) -> dict:
        try:
            backups = sorted(Path(self.dir).glob('securebot_*.db.gz'))
            total_size = sum(f.stat().st_size for f in backups)
            latest = backups[-1].name if backups else 'Noch keins'
            return {'count': len(backups), 'latest': latest, 'total_kb': total_size // 1024}
        except Exception:
            return {'count': 0, 'latest': 'Fehler', 'total_kb': 0}


# ============================================================
# Guardian - Orchestrator
# ============================================================
class Guardian:
    def __init__(self, cfg: GuardianConfig):
        self.cfg = cfg
        self.alert = AlertManager(cfg.TELEGRAM_TOKEN, cfg.ADMIN_USER_ID)
        self.sys = SystemMonitor(cfg.PROC_PATH)
        self.docker = DockerMonitor()
        self.db = DatabaseMonitor()
        self.fim = FileIntegrityMonitor()
        self.ssh = SSHMonitor(cfg.LOG_PATH)
        self.backup = BackupManager(cfg.BACKUP_DIR, cfg.BACKUP_RETENTION_DAYS)
        self.start_time = datetime.now()
        self.last_db_size = 0
        self.last_backup_date = None
        self.last_report_date = None
        self.last_restart_count = 0
        # Tages-Maxima fuer Report
        self.max_cpu = 0.0
        self.max_ram = 0.0

    async def run(self):
        logger.info("Guardian startet...")
        self.fim.create_baseline()

        # Erste CPU-Messung (braucht 2 Lesungen)
        self.sys.get_cpu()
        await asyncio.sleep(2)

        await self.alert.send("INFO", "Guardian gestartet",
            f"Ueberwache: {self.cfg.BOT_CONTAINER}\n"
            f"DB: {self.cfg.DB_PATH}\n"
            f"Check-Intervall: {self.cfg.CHECK_INTERVAL}s\n"
            f"Backup: taeglich {self.cfg.BACKUP_HOUR}:00 UTC")

        while True:
            try:
                await self._check_system()
                await self._check_docker()
                await self._check_db()
                await self._check_fim()
                await self._check_ssh()
                await self._check_backup()
                await self._check_report()
                self._write_status()
            except Exception as e:
                logger.error(f"Check-Schleife Fehler: {e}")

            await asyncio.sleep(self.cfg.CHECK_INTERVAL)

    async def _check_system(self):
        cpu = self.sys.get_cpu()
        mem = self.sys.get_memory()
        disk = self.sys.get_disk()
        load = self.sys.get_load()

        if cpu > 0:
            self.max_cpu = max(self.max_cpu, cpu)
        if mem['percent'] > 0:
            self.max_ram = max(self.max_ram, mem['percent'])

        if cpu > self.cfg.CPU_WARN:
            await self.alert.send("WARNING", "CPU hoch",
                f"CPU: {cpu}%\nLoad: {load}", key="cpu_high")

        if mem['percent'] >= self.cfg.RAM_CRIT:
            await self.alert.send("CRITICAL", "RAM kritisch",
                f"RAM: {mem['percent']}% ({mem['used_mb']}/{mem['total_mb']} MB)\n"
                f"Frei: {mem['avail_mb']} MB", key="ram_crit")
        elif mem['percent'] >= self.cfg.RAM_WARN:
            await self.alert.send("WARNING", "RAM hoch",
                f"RAM: {mem['percent']}% ({mem['used_mb']}/{mem['total_mb']} MB)", key="ram_high")

        if disk['percent'] >= self.cfg.DISK_CRIT:
            await self.alert.send("CRITICAL", "Speicher kritisch",
                f"Disk: {disk['percent']}% ({disk['used_gb']}/{disk['total_gb']} GB)", key="disk_crit")
        elif disk['percent'] >= self.cfg.DISK_WARN:
            await self.alert.send("WARNING", "Speicher hoch",
                f"Disk: {disk['percent']}% ({disk['used_gb']}/{disk['total_gb']} GB)", key="disk_high")

    async def _check_docker(self):
        status = self.docker.get_status(self.cfg.BOT_CONTAINER)

        if not status['running']:
            await self.alert.send("CRITICAL", "Bot Container DOWN",
                f"Container '{self.cfg.BOT_CONTAINER}' ist NICHT aktiv!\n"
                f"Status: {status['status']}", key="bot_down")

        if status['restarts'] > self.last_restart_count:
            await self.alert.send("WARNING", "Bot neugestartet",
                f"Restart-Count: {status['restarts']} (vorher: {self.last_restart_count})\n"
                f"Gestartet: {status.get('started', '?')}", key="bot_restart")
            self.last_restart_count = status['restarts']

    async def _check_db(self):
        ok, result = self.db.check_integrity(self.cfg.DB_PATH)
        if not ok:
            await self.alert.send("CRITICAL", "DB Integritaet FEHLGESCHLAGEN",
                f"PRAGMA integrity_check: {result}", key="db_integrity")

        size_kb = self.db.get_size_kb(self.cfg.DB_PATH)
        if size_kb > self.cfg.DB_MAX_SIZE_MB * 1024:
            await self.alert.send("WARNING", "DB zu gross",
                f"Groesse: {size_kb} KB ({size_kb // 1024} MB)\n"
                f"Limit: {self.cfg.DB_MAX_SIZE_MB} MB", key="db_size")

        if self.last_db_size > 0 and size_kb > 0:
            growth = (size_kb - self.last_db_size) / self.last_db_size
            if growth > self.cfg.DB_GROWTH_WARN:
                await self.alert.send("WARNING", "DB Wachstumsanomalie",
                    f"{self.last_db_size} KB -> {size_kb} KB (+{growth*100:.0f}%)\n"
                    f"In {self.cfg.CHECK_INTERVAL}s", key="db_growth")
        self.last_db_size = size_kb

    async def _check_fim(self):
        changed = self.fim.check()
        if changed:
            files_str = '\n'.join(f"• {f}" for f in changed)
            await self.alert.send("CRITICAL", "DATEI VERAENDERT",
                f"Folgende Dateien wurden modifiziert:\n{files_str}\n\n"
                f"Moeglicher Einbruch!", key=None)  # Kein Dedup fuer FIM!

    async def _check_ssh(self):
        result = self.ssh.check()
        total = result['total']
        ips = result['ips']

        if total >= self.cfg.SSH_FAIL_CRIT_TOTAL:
            top = sorted(ips.items(), key=lambda x: x[1], reverse=True)[:5]
            top_str = '\n'.join(f"• {ip}: {c}x" for ip, c in top)
            await self.alert.send("CRITICAL", "SSH unter Beschuss",
                f"Total: {total} fehlgeschlagene Logins\n"
                f"Unique IPs: {len(ips)}\n\nTop Angreifer:\n{top_str}", key="ssh_crit")
        else:
            for ip, count in ips.items():
                if count >= self.cfg.SSH_FAIL_WARN_PER_IP:
                    await self.alert.send("WARNING", "SSH Brute-Force",
                        f"{count} fehlgeschlagene Logins von {ip}", key=f"ssh_{ip}")

    async def _check_backup(self):
        now = datetime.now()
        if now.hour == self.cfg.BACKUP_HOUR and self.last_backup_date != now.date():
            self.last_backup_date = now.date()
            logger.info("Starte taegliches Backup...")

            ok, result = self.backup.create(self.cfg.DB_PATH)
            if ok:
                self.backup.rotate()
                info = self.backup.info()
                logger.info(f"Backup OK: {info['count']} Backups, {info['total_kb']} KB")
            else:
                await self.alert.send("CRITICAL", "Backup FEHLGESCHLAGEN",
                    f"Fehler: {result}", key=None)

    async def _check_report(self):
        now = datetime.now()
        if now.hour == self.cfg.REPORT_HOUR and self.last_report_date != now.date():
            self.last_report_date = now.date()
            report = await self._generate_report()
            await self.alert.send_report(report)
            # Reset Tages-Werte
            self.max_cpu = 0.0
            self.max_ram = 0.0
            self.ssh.reset_daily()

    async def _generate_report(self) -> str:
        mem = self.sys.get_memory()
        disk = self.sys.get_disk()
        cpu = self.sys.get_cpu()
        load = self.sys.get_load()
        docker = self.docker.get_status(self.cfg.BOT_CONTAINER)
        db_size = self.db.get_size_kb(self.cfg.DB_PATH)
        users = self.db.get_user_count(self.cfg.DB_PATH)
        queries = self.db.get_today_queries(self.cfg.DB_PATH)
        ssh = self.ssh.check()
        ok, _ = self.db.check_integrity(self.cfg.DB_PATH)
        bk = self.backup.info()
        fim = self.fim.check()
        uptime = (datetime.now() - self.start_time).total_seconds() / 3600

        return (
            f"\U0001f4cb **Taeglicher SOC-Report**\n"
            f"_{datetime.now().strftime('%d.%m.%Y')}_\n\n"
            f"**System:**\n"
            f"\u2022 CPU: {cpu}% (Max: {self.max_cpu}%)\n"
            f"\u2022 RAM: {mem['percent']}% ({mem['used_mb']}/{mem['total_mb']} MB)\n"
            f"\u2022 Disk: {disk['percent']}% ({disk['used_gb']}/{disk['total_gb']} GB)\n"
            f"\u2022 Load: {load}\n\n"
            f"**Bot:**\n"
            f"\u2022 Status: {'Running' if docker['running'] else 'DOWN!'}\n"
            f"\u2022 Restarts: {docker['restarts']}\n"
            f"\u2022 Users: {users}\n"
            f"\u2022 Queries heute: {queries}\n\n"
            f"**Daten:**\n"
            f"\u2022 DB: {db_size} KB | Integritaet: {'OK' if ok else 'FEHLER!'}\n"
            f"\u2022 Backup: {bk['latest']} ({bk['count']} gesamt, {bk['total_kb']} KB)\n\n"
            f"**Sicherheit:**\n"
            f"\u2022 SSH Failed: {ssh['total']} ({len(ssh['ips'])} IPs)\n"
            f"\u2022 File Integrity: {'OK' if not fim else 'WARNUNG!'}\n"
            f"\u2022 Alerts heute: {self.alert.alerts_today}\n\n"
            f"_Guardian Uptime: {uptime:.1f}h_"
        )

    def _write_status(self):
        try:
            mem = self.sys.get_memory()
            disk = self.sys.get_disk()
            bk = self.backup.info()
            uptime = (datetime.now() - self.start_time).total_seconds() / 3600

            status = {
                'last_check': datetime.now().strftime('%H:%M:%S'),
                'uptime_hours': round(uptime, 1),
                'alerts_today': self.alert.alerts_today,
                'last_backup': bk['latest'],
                'db_size_kb': self.db.get_size_kb(self.cfg.DB_PATH),
                'cpu_percent': self.sys.get_cpu(),
                'ram_percent': mem['percent'],
                'disk_percent': disk['percent'],
                'bot_running': self.docker.get_status(self.cfg.BOT_CONTAINER).get('running', False),
                'backup_count': bk['count'],
                'ssh_failed_today': self.ssh.total_failed,
            }

            tmp = f'{self.cfg.STATUS_FILE}.tmp'
            with open(tmp, 'w') as f:
                json.dump(status, f)
            os.replace(tmp, self.cfg.STATUS_FILE)
        except Exception as e:
            logger.error(f"Status-File Fehler: {e}")


# ============================================================
# Main
# ============================================================
def main():
    cfg = GuardianConfig()

    if not cfg.TELEGRAM_TOKEN or not cfg.ADMIN_USER_ID:
        logger.error("TELEGRAM_TOKEN oder ADMIN_USER_ID nicht gesetzt!")
        return

    guardian = Guardian(cfg)
    asyncio.run(guardian.run())


if __name__ == '__main__':
    main()
