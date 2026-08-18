#!/usr/bin/env python
"""Сброс выборов перед новой игрой - только очистка.

Удаляет папки с документами предыдущей игры ЦЕЛИКОМ (вместе с файлами и
вложенными папками), включая meta. Ничего не создаёт: папки появляются заново
при следующем запуске агентства (./agency.py) - оно публикует meta (ключ
регистратора, кандидатов, фазу REGISTRATION) и стену.

Запуск:  ./reset.py   (из папки игры, настройки из config.json)
"""
import ftplib
import time

import protocol as pr

# Папки, которые сбрасываются целиком (meta целиком: ключ, кандидаты, фазы)
GAME_FOLDERS = [pr.F_SIGN_REQUESTS, pr.F_SIGN_RESULTS, pr.F_MARKS,
                pr.F_AUTHORIZED_KEYS, pr.F_BALLOTS, pr.F_SECRET_KEYS,
                "meta"]


def _retry(fn, attempts=3):
    last = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:
            last = e
            time.sleep(2 * (i + 1))
    raise last


def _list_items(ftp, folder, home_abs):
    """(имя, тип) содержимого папки. Вызывается, когда cwd уже внутри folder.

    MLSD - где поддерживается; иначе NLST + проверка «заходится ли как в папку»
    (на многих серверах NLST не отличает папку от файла и не ставит '/').
    Мусорные '.' и '..' отбрасываются."""
    try:
        return [(n, "dir" if f.get("type") == "dir" else "file")
                for n, f in _retry(lambda: list(ftp.mlsd()))
                if n not in (".", "..")]
    except Exception:
        pass
    try:
        raw = _retry(lambda: ftp.nlst())
    except Exception:
        return []
    out = []
    for n in raw:
        name = n.rstrip("/")
        if name in (".", ".."):
            continue
        try:
            ftp.cwd(name)          # вошёл как в папку - значит папка
            out.append((name, "dir"))
        except Exception:
            out.append((name, "file"))
        finally:
            ftp.cwd(home_abs)      # вернуться к корню базы и снова в папку
            ftp.cwd(folder)
    return out


def remove_folder(ftp, folder, home="/"):
    """Удалить папку целиком: файлы, вложенные папки, потом саму папку.
    Возвращает число удалённых файлов. Папок, которых нет, - просто пропускает."""
    home_abs = home if home.startswith("/") else "/" + home
    try:
        ftp.cwd(home_abs)
        ftp.cwd(folder)
    except ftplib.all_errors:
        print("нет папки:", folder)
        return 0

    items = _list_items(ftp, folder, home_abs)
    ftp.cwd(home_abs)

    count = 0
    for name, typ in items:
        path = f"{folder}/{name}"
        if typ == "dir":
            count += remove_folder(ftp, path, home)
        else:
            try:
                ftp.delete(path)
                count += 1
            except Exception as e:
                print("не удалился:", path, e)
    try:
        ftp.rmd(folder)
        print("удалена папка:", folder)
    except Exception as e:
        print("не удалилась папка:", folder, e)
    return count


def _connect_ftp(ftp_cfg):
    """Подключиться с повторами - сервер может капризничать."""
    last = None
    for i in range(4):
        ftp = ftplib.FTP()
        try:
            ftp.connect(ftp_cfg["host"], ftp_cfg["port"], timeout=60)
            ftp.login(ftp_cfg["user"], ftp_cfg["password"])
            ftp.voidcmd("TYPE I")
            return ftp
        except Exception as e:
            last = e
            try:
                ftp.close()
            except Exception:
                pass
            print(f"не подключились (попытка {i + 1}/4): {e}")
            time.sleep(3 * (i + 1))
    raise last


def main():
    cfg = pr.load_config("config.json")
    ftp_cfg = cfg["ftp"]

    ftp = _connect_ftp(ftp_cfg)

    base = ftp_cfg.get("base_path", "").strip("/")
    home = "/" + base if base else "/"
    if base:
        ftp.cwd(home)

    total = 0
    for folder in GAME_FOLDERS:
        total += remove_folder(ftp, folder, home)
    ftp.quit()

    print("RESET_OK: удалено файлов:", total)
    print("Все папки игры очищены.")
    print("Запусти агентство: ./agency.py - оно создаст meta заново "
          "(ключ регистратора, кандидаты, фазу REGISTRATION) и стену.")


if __name__ == "__main__":
    main()
