#!/usr/bin/env python
import argparse
import os
import random
import re
import threading

import lib_blind
import protocol as pr
import view
from qr import decode_qr_from_image
from termux import capture_photo, vibrate


def parse_accept(cmd):
    """Вытащить номер метки из команды accept.

    Принимает и «accept 17», и вставленную целиком строку с экрана участника
    («Привет, чел! Твоя метка: 565…»), и скопированное с переводом строки.
    Возвращает int или None, если номер не найден.
    """
    parts = cmd.strip().split()
    if len(parts) < 2:
        return None
    m = re.search(r"\d+", " ".join(parts[1:]))
    return int(m.group()) if m else None


class AgencyEngine:
    def __init__(self, store, candidates, election="Выборы",
                 key_path="registrar_privkey.pem",
                 batch_size=3, batch_seconds=25):
        self.store = store
        self.candidates = candidates
        self.election = election
        self.key_path = key_path
        self.batch_size = batch_size
        self.batch_seconds = batch_seconds
        self._pending_marks = []
        self._pending_signs = []
        self._load_or_create_registrar_key(key_path)

    def _load_or_create_registrar_key(self, key_path):
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                self._priv = lib_blind.import_private_key(f.read())
            self._pub = self._priv.publickey()
        else:
            self._pub, self._priv = lib_blind.keygen(2048)
            with open(key_path, "wb") as f:
                f.write(lib_blind.export_private_key(self._priv))
            os.chmod(key_path, 0o600)

    def start(self, config_path=None):
        if not self.store.exists(pr.META_PUBKEY):
            self.store.upload_text(pr.META_PUBKEY, pr.pubkey_to_pem(self._pub) + "\n")
            self.store.upload_text(pr.META_CANDIDATES,
                                   pr.pretty_json({"election": self.election,
                                                   "candidates": self.candidates}) + "\n")
            self.store.upload_json(pr.META_PHASE_DIR, "REGISTRATION",
                                   {"phase": "REGISTRATION", "set_at": pr.iso_now()})
        if config_path and os.path.exists(config_path):
            # публикуем свой config.json - участники берут настройки с сервера
            with open(config_path, "r", encoding="utf-8") as f:
                self.store.upload_text("config.json", f.read())

    def phase(self):
        return pr.current_phase(self.store)

    def set_phase(self, phase):
        if phase not in pr.VALID_PHASES:
            raise ValueError(f"нет такой фазы: {phase}")
        self.store.upload_json(pr.META_PHASE_DIR, phase,
                               {"phase": phase, "set_at": pr.iso_now()})

    def approve_mark(self, mark):
        self._pending_marks.append(int(mark))

    def public_approved_marks(self):
        return sorted(int(m["mark"]) for m in self.store.list_folder(pr.F_MARKS))

    def flush_pending(self):
        random.shuffle(self._pending_marks)
        while self._pending_marks:
            batch = self._pending_marks[: self.batch_size]
            for m in batch:
                self.store.upload_json(pr.F_MARKS, str(m),
                                       {"mark": m, "approved_at": pr.iso_now()})
            self._pending_marks = self._pending_marks[self.batch_size:]
        random.shuffle(self._pending_signs)
        while self._pending_signs:
            batch = self._pending_signs[: self.batch_size]
            for s in batch:
                self.store.upload_json(pr.F_SIGN_RESULTS, str(s["mark"]), s)
            self._pending_signs = self._pending_signs[self.batch_size:]

    def process_once(self):
        approved = set(self.public_approved_marks())
        reqs = self.store.list_folder(pr.F_SIGN_REQUESTS)
        results = self.store.list_folder(pr.F_SIGN_RESULTS)
        done = {(int(r["mark"]), int(r["blinded"])) for r in results}
        count = 0
        for req in reqs:
            mk, bl = int(req["mark"]), int(req["blinded"])
            if mk in approved and (mk, bl) not in done:
                sig = pow(bl, self._priv.d, self._priv.n)
                self._pending_signs.append({"mark": mk, "blinded": bl, "sign": sig})
                count += 1
        return count


def _tick_loop(agency, stop):
    while not stop.is_set():
        try:
            n = agency.process_once()
            agency.flush_pending()
            if n:
                print(f"подписано новых запросов: {n}")
        except Exception as e:
            print("фоновая обработка:", e)
        stop.wait(agency.batch_seconds)


def _wall_loop(store, stop, interval):
    if interval < 1:
        interval = 1
    while not stop.is_set():
        try:
            view.publish_wall(store)
        except Exception as e:
            print("стена:", e)
        stop.wait(interval)


def _console(agency, store, stop):
    while True:
        try:
            cmd = input("агентство> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        parts = cmd.split()
        if not parts:
            continue
        c = parts[0]
        try:
            if c in ("q", "выход"):
                break
            elif c == "marks":
                print("Допущенные метки:", agency.public_approved_marks())
            elif c == "status":
                print("Фаза:", agency.phase())
                print("Допущенные метки:", agency.public_approved_marks())
                print("Авторизованных ключей:", len(store.list_folder(pr.F_AUTHORIZED_KEYS)))
                print("Бюллетеней:", len(store.list_folder(pr.F_BALLOTS)))
                print("Ключей расшифровки:", len(store.list_folder(pr.F_SECRET_KEYS)))
            elif c == "accept":
                mark = parse_accept(cmd)
                if mark is None:
                    print("accept <метка> - например: accept 17 (можно вставить метку как есть)")
                    continue
                agency.approve_mark(mark)
                print(f"метка {mark} в очереди на публикацию (пачками)")
            elif c == "flush":
                agency.flush_pending()
                print("очередь отправлена")
            elif c == "scan":
                import os as _os
                import tempfile as _tmp
                p = _os.path.join(_tmp.gettempdir(), "cam.jpg")
                if not capture_photo(p):
                    print("не удалось снять камерой (termux-api?). Введи вручную: accept <метка>")
                    continue
                mark = decode_qr_from_image(p)
                if mark is None:
                    print("QR не распознан. Введи метку вручную: accept <метка>")
                    continue
                print("В кадре метка #", mark)
                vibrate()
                agency.approve_mark(mark)
            elif c == "phase":
                if len(parts) < 2:
                    print("phase <ФАЗА> - " + " | ".join(pr.PHASES))
                    continue
                agency.set_phase(parts[1].upper())
                print("Фаза:", agency.phase())
            elif c == "help":
                print("scan | accept <метка> | marks | flush | phase <ФАЗА> | status | q")
                print("Фазы:", " | ".join(pr.PHASES))
            else:
                print("неизвестная команда. help")
        except Exception as e:
            print(f"Ошибка: {e} - команда не выполнена (help)")


def main():
    ap = argparse.ArgumentParser(description="Агентство: регистратор + публикация стены")
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--wall-interval", type=int, default=15,
                    help="как часто перезаливать стену, секунд (по умолчанию 15)")
    args = ap.parse_args()

    cfg = pr.load_config(args.config)
    store = pr.make_store(cfg)
    agency = AgencyEngine(store, cfg["candidates"], cfg["election"],
                          batch_seconds=cfg["agency"]["batch_seconds"],
                          key_path=cfg["agency"]["key_path"])
    agency.start(config_path=args.config)
    print("Агентство запущено. Фаза:", agency.phase())

    stop = threading.Event()
    threading.Thread(target=_tick_loop, args=(agency, stop), daemon=True).start()
    threading.Thread(target=_wall_loop, args=(store, stop, args.wall_interval),
                     daemon=True).start()
    print(f"Стена публикуется на FTP: meta/index.html (каждые {args.wall_interval} сек)")
    print("Открыть в браузере: https://mapavlov.ru/vote-game/meta/index.html")
    print("(ftp:// в браузерах не открывается - страница раздаётся по HTTPS и обновляется сама)")
    _console(agency, store, stop)


if __name__ == "__main__":
    main()
