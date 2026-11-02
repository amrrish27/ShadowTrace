"""ShadowTrace runner -- starts API (with training lab) and worker together."""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND = REPO_ROOT / "backend"
DATA = REPO_ROOT / "data"
LOGS = REPO_ROOT / "logs"


def main() -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)

    secret_key_file = DATA / "secret.key"
    if not secret_key_file.is_file():
        import secrets
        secret_key_file.write_text(secrets.token_urlsafe(48), encoding="utf-8")
    secret_key = secret_key_file.read_text(encoding="utf-8").strip()

    api_port = os.environ.get("PORT") or os.environ.get("API_PORT", "8000")
    api_host = os.environ.get("HOST", "0.0.0.0")
    lab_port = os.environ.get("LAB_PORT", "8099")

    allowed_hosts = os.environ.get("ST_ALLOWED_HOSTS") or "localhost,127.0.0.1,0.0.0.0,*"
    cors_origins = os.environ.get("ST_CORS_ORIGINS") or f"http://localhost:{api_port},http://127.0.0.1:{api_port},*"

    env = os.environ.copy()
    env.update({
        "ST_ENV": os.environ.get("ST_ENV", "development"),
        "ST_SECRET_KEY": os.environ.get("ST_SECRET_KEY", secret_key),
        "ST_DATABASE_PATH": os.environ.get("ST_DATABASE_PATH", str(DATA / "shadowtrace.db")),
        "ST_BASE_URL": os.environ.get("ST_BASE_URL", f"http://localhost:{api_port}"),
        "ST_ALLOWED_HOSTS": allowed_hosts,
        "ST_CORS_ORIGINS": cors_origins,
        "ST_COOKIE_SECURE": os.environ.get("ST_COOKIE_SECURE", "false"),
        "ST_LOG_LEVEL": os.environ.get("ST_LOG_LEVEL", "INFO"),
        "ST_SCANNING_ENABLED": "true",
        "ST_PRIVATE_ALLOWLIST": os.environ.get("ST_PRIVATE_ALLOWLIST", f"127.0.0.1:{lab_port}"),
        "ST_LAB_ENABLED": os.environ.get("ST_LAB_ENABLED", "true"),
        "ST_LAB_HOST": "127.0.0.1",
        "ST_LAB_PORT": str(lab_port),
        "ST_LAB_AUTOSTART": os.environ.get("ST_LAB_AUTOSTART", "true"),
        "ST_DEMO_MODE": "false",
        "ST_BOOTSTRAP_ADMIN_EMAIL": os.environ.get("ST_BOOTSTRAP_ADMIN_EMAIL", "admin@example.test"),
        "ST_BOOTSTRAP_ADMIN_PASSWORD": os.environ.get("ST_BOOTSTRAP_ADMIN_PASSWORD", "Bootstrap-Admin-Pass-9!"),
        "ST_BOOTSTRAP_ORG_NAME": os.environ.get("ST_BOOTSTRAP_ORG_NAME", "ShadowTrace Local"),
    })

    print("[info] applying migrations...")
    subprocess.run([sys.executable, "-m", "app.cli", "init"], cwd=str(BACKEND), env=env, check=True)

    print("[info] ensuring admin user exists...")
    bootstrap_script = (
        "import os, sys\n"
        "sys.path.insert(0, 'backend')\n"
        "from app.db import db, new_id, now\n"
        "from app.security.passwords import hash_password\n"
        "email = os.environ.get('ST_BOOTSTRAP_ADMIN_EMAIL', 'admin@example.test').lower().strip()\n"
        "password = os.environ.get('ST_BOOTSTRAP_ADMIN_PASSWORD', 'Bootstrap-Admin-Pass-9!')\n"
        "org_name = os.environ.get('ST_BOOTSTRAP_ORG_NAME', 'ShadowTrace Local')\n"
        "with db() as conn:\n"
        "    row = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()\n"
        "    if row is None:\n"
        "        org_row = conn.execute('SELECT id FROM organizations WHERE name = ?', (org_name,)).fetchone()\n"
        "        if org_row is None:\n"
        "            org_id = new_id()\n"
        "            conn.execute('INSERT INTO organizations (id, name, created_at) VALUES (?, ?, ?)', (org_id, org_name, now()))\n"
        "        else:\n"
        "            org_id = str(org_row['id'])\n"
        "        user_id = new_id()\n"
        "        conn.execute(\n"
        "            'INSERT INTO users (id, org_id, email, name, role, password_hash, is_active, created_at) VALUES (?, ?, ?, ?, \"admin\", ?, 1, ?)',\n"
        "            (user_id, org_id, email, 'Administrator', hash_password(password), now()),\n"
        "        )\n"
        "        print(f'[ok] created bootstrap admin: {email}')\n"
        "    else:\n"
        "        conn.execute('UPDATE users SET password_hash = ?, is_active = 1 WHERE email = ?', (hash_password(password), email))\n"
        "        print(f'[ok] verified admin password for: {email}')\n"
    )
    subprocess.run([sys.executable, "-c", bootstrap_script], cwd=str(REPO_ROOT), env=env, check=True)

    api_log = open(LOGS / "api.log", "w", encoding="utf-8")
    worker_log = open(LOGS / "worker.log", "w", encoding="utf-8")

    print("[info] starting API and lab...")
    api_proc = subprocess.Popen(
        [sys.executable, str(REPO_ROOT / "scripts" / "run_service.py"), "api", "--host", str(api_host), "--port", str(api_port)],
        cwd=str(BACKEND),
        env=env,
    )

    print("[info] starting worker...")
    worker_proc = subprocess.Popen(
        [sys.executable, str(REPO_ROOT / "scripts" / "run_service.py"), "worker"],
        cwd=str(BACKEND),
        env=env,
    )

    print(f"[ok] API started (PID {api_proc.pid}), worker started (PID {worker_proc.pid})")
    print(f"ShadowTrace UI + API : http://127.0.0.1:{api_port}/")
    print(f"ShadowLab training   : http://127.0.0.1:{lab_port}/")
    print("Sign in              : admin@example.test / Bootstrap-Admin-Pass-9!")

    def cleanup(*_args):
        print("\n[info] stopping services...")
        for proc in (api_proc, worker_proc):
            try:
                proc.terminate()
            except Exception:
                pass
        for proc in (api_proc, worker_proc):
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
        api_log.close()
        worker_log.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    try:
        while True:
            if api_proc.poll() is not None:
                print(f"[warn] API process exited with code {api_proc.returncode}")
                cleanup()
            if worker_proc.poll() is not None:
                print(f"[warn] worker process exited with code {worker_proc.returncode}")
                cleanup()
            time.sleep(1)
    except KeyboardInterrupt:
        cleanup()


if __name__ == "__main__":
    main()
