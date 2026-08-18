#!/usr/bin/env python
import argparse
import ftplib
import os
import time

import protocol as pr
from view import load_public_state, print_report


def main():
    ap = argparse.ArgumentParser(
        description="Независимая проверка голосов из публичных файлов FTP. "
                    "Настройки берутся из config.json - просто запусти: ./verify.py")
    ap.add_argument("--config", default="config.json", help="файл настроек (по умолчанию config.json)")
    ap.add_argument("--host", help="адрес FTP-сервера (переопределяет config.json)")
    ap.add_argument("--port", type=int, help="порт FTP (по умолчанию из config.json, иначе 21)")
    ap.add_argument("--user", help="логин FTP (переопределяет config.json)")
    ap.add_argument("--password", help="пароль FTP (переопределяет config.json)")
    ap.add_argument("--base-path", help="папка на сервере с документами (переопределяет config.json)")
    args = ap.parse_args()

    if os.path.exists(args.config):
        cfg = pr.load_config(args.config)
    else:
        cfg = {}
    ftp = cfg.setdefault("ftp", {})
    if args.host:
        ftp["host"] = args.host
    if args.port:
        ftp["port"] = args.port
    if args.user:
        ftp["user"] = args.user
    if args.password:
        ftp["password"] = args.password
    if args.base_path:
        ftp["base_path"] = args.base_path
    ftp.setdefault("port", 21)

    if not ftp.get("host"):
        print("Не задан адрес FTP-сервера.")
        print("Просто запусти ./verify.py из папки игры - настройки возьмутся из config.json.")
        print("Либо передай вручную: ./verify.py --host <сервер> --user <логин> --password <пароль>")
        return 1

    store = pr.make_store(cfg)
    for attempt in range(3):
        try:
            print_report(load_public_state(store))
            return 0
        except (ftplib.all_errors, OSError) as e:
            if attempt < 2:
                print(f"сервер капризничает (попытка {attempt + 1}/3): {e}")
                time.sleep(3 * (attempt + 1))
                continue
            print("Не удалось получить документы с FTP:", e)
            print("Проверь сеть и повтори: ./verify.py")
            return 1


if __name__ == "__main__":
    main()
