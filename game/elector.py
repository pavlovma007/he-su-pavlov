#!/usr/bin/env python
import argparse
import base64
import ftplib
import hashlib
import json
import os
import random
import time

import pyaes

import lib_blind
import protocol as pr
from qr import render_qr_terminal


class ElectorEngine:
    def __init__(self, store, nickname="", key_path="elector_privkey.pem"):
        self.store = store
        self.nickname = nickname
        self.key_path = key_path
        self.mark_1 = None
        self.mark_2 = None
        self.public_key = None
        self.private_key = None
        self.registrar_pub = None
        self.election = None
        self.candidates = []
        self._blinded = None
        self._blind_r = None
        self.signed_hash = None
        self._authorized_uploaded = False
        self.secret_key = None
        self.ballot = None
        self.load_public_meta()

    def load_public_meta(self):
        self.registrar_pub = pr.pem_to_pubkey(self.store.read_text(pr.META_PUBKEY))
        meta = json.loads(self.store.read_text(pr.META_CANDIDATES))
        self.election = meta["election"]
        self.candidates = meta["candidates"]

    def phase(self):
        return pr.current_phase(self.store)

    def _derive_mark(self, salt):
        der = self.public_key.export_key(format="DER")
        h = hashlib.sha256(der + salt).digest()
        return int.from_bytes(h, "big") % 2 ** 63

    def generate_mark(self, mark_1=None):
        # Метка выводится из ключа: перезапуск — та же метка, та же личность.
        if mark_1 is not None:
            self.mark_1 = mark_1
        elif self.public_key is not None:
            self.mark_1 = self._derive_mark(b"mark-1")
        else:
            self.mark_1 = random.randint(2, 2 ** 63)
        return self.mark_1

    def generate_mark2(self, mark_2=None):
        if mark_2 is not None:
            self.mark_2 = mark_2
        elif self.public_key is not None:
            self.mark_2 = self._derive_mark(b"mark-2")
        else:
            self.mark_2 = random.randint(2, 2 ** 63)
        return self.mark_2

    def generate_keys(self):
        self.public_key, self.private_key = lib_blind.keygen(2048)
        with open(self.key_path, "wb") as f:
            f.write(lib_blind.export_private_key(self.private_key))
        os.chmod(self.key_path, 0o600)

    def load_or_create_keys(self):
        """Ключ с прошлого запуска = та же личность. Нет ключа — создаём новый."""
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                self.private_key = lib_blind.import_private_key(f.read())
            self.public_key = self.private_key.publickey()
        else:
            self.generate_keys()

    def _derive_secret_key(self):
        """Детерминированный ключ шифрования бюллетеня: если телефон перезапустят
        после голосования, ключ расшифровки не потеряется."""
        der = self.private_key.export_key(format="DER")
        h = hashlib.sha256(der + str(self.mark_2).encode("utf-8")).digest()
        return h[:16]

    def register_begin(self):
        pub_der = self.public_key.export_key(format="DER")
        self._blinded, self._blind_r = lib_blind.blind(pub_der, self.registrar_pub)
        req = pr.make_sign_request(self.mark_1, self._blinded)
        self.store.upload_json(pr.F_SIGN_REQUESTS, str(self.mark_1), req)
        return pr.pretty_json({"mark": self.mark_1})

    def is_approved(self):
        return any(int(m["mark"]) == self.mark_1
                   for m in self.store.list_folder(pr.F_MARKS))

    def try_fetch_signature(self):
        for s in self.store.list_folder(pr.F_SIGN_RESULTS):
            if int(s["mark"]) == self.mark_1 and int(s["blinded"]) == self._blinded:
                self.signed_hash = lib_blind.unblind(int(s["sign"]), self._blind_r,
                                                     self.registrar_pub)
                return True
        return False

    def try_authorize(self):
        if self.signed_hash is None:
            return False
        if not self._authorized_uploaded:
            pem = pr.pubkey_to_pem(self.public_key)
            payload = pr.make_authorize_payload(pem, self.signed_hash)
            self.store.upload_json(pr.F_AUTHORIZED_KEYS, str(self.mark_1), payload)
            self._authorized_uploaded = True
        return True

    def is_authorized(self):
        pem = pr.pubkey_to_pem(self.public_key)
        return any(a.get("public_key_pem") == pem
                   for a in self.store.list_folder(pr.F_AUTHORIZED_KEYS))

    def find_my_ballot(self):
        """Бюллетень этой метки на FTP — понятно, проголосовал ли уже участник."""
        pem = pr.pubkey_to_pem(self.public_key)
        for b in self.store.list_folder(pr.F_BALLOTS):
            if int(b.get("mark_2")) == self.mark_2 and b.get("public_key_pem") == pem:
                self.ballot = b
                return b
        return None

    def vote(self, candidate_id):
        self.secret_key = self._derive_secret_key()
        aes = pyaes.AESModeOfOperationCTR(self.secret_key)
        ct = aes.encrypt(str(candidate_id).encode("utf-8"))
        ct_b64 = base64.b64encode(ct).decode("ascii")
        ballot_sign = lib_blind.signature(ct, self.private_key)
        pem = pr.pubkey_to_pem(self.public_key)
        self.ballot = pr.make_ballot(self.mark_2, pem, ct_b64, ballot_sign)
        self.store.upload_json(pr.F_BALLOTS, str(self.mark_2), self.ballot)

    def ballot_published(self):
        if self.ballot is None:
            return False
        return any(b.get("ballot_enc_b64") == self.ballot["ballot_enc_b64"]
                   for b in self.store.list_folder(pr.F_BALLOTS))

    def secret_key_published(self):
        return any(int(s.get("mark_2")) == self.mark_2
                   for s in self.store.list_folder(pr.F_SECRET_KEYS))

    def submit_secret_key(self):
        if self.secret_key is None:
            return
        sk_b64 = base64.b64encode(self.secret_key).decode("ascii")
        key_sign = lib_blind.signature(self.secret_key, self.private_key)
        pem = pr.pubkey_to_pem(self.public_key)
        payload = pr.make_secret_key(self.mark_2, pem, sk_b64, key_sign)
        self.store.upload_json(pr.F_SECRET_KEYS, str(self.mark_2), payload)


def _try_authorize(e):
    """Пытается опубликовать авторизацию ключа и проверяет её появление.
    Транзиентные ошибки FTP не роняют мастер — возвращается False, и вызов
    повторяется следующим опросом _wait_until."""
    try:
        e.try_authorize()
        return e.is_authorized()
    except Exception:
        return False


def _save_config(cfg, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n")


def _load_or_fetch_config(config_path):
    """Берём config.json с сервера — его публикует агентство при запуске.

    Локальный файл — просто кэш для старта и офлайна. Если его нет, один раз
    спрашиваем адрес сервера и дальше тянем полный config оттуда же.
    """
    cfg = None
    if os.path.exists(config_path):
        try:
            cfg = pr.load_config(config_path)
        except Exception as e:
            print("⚠️ Не прочитался локальный config.json:", e)
    if cfg is None:
        print("Локального config.json нет — спрошу, где сервер игры.")
        host = input("Адрес FTP-сервера: ").strip()
        user = input("Логин FTP: ").strip()
        password = input("Пароль FTP: ").strip()
        cfg = {"ftp": {"host": host, "port": 21, "user": user,
                       "password": password, "base_path": ""}}
    store = pr.make_store(cfg)
    try:
        server_cfg = json.loads(store.read_text("config.json"))
        _save_config(server_cfg, config_path)
        return server_cfg, pr.make_store(server_cfg)
    except Exception as e:
        print("⚠️ Не удалось взять config.json с сервера, использую локальный:", e)
        return cfg, store


def _wait_until(pred, what, timeout=None):
    """Ждать сколько нужно. timeout=None — бесконечно, выход только Ctrl+C:
    участник может ждать регистратора сколько угодно."""
    start = time.time()
    while timeout is None or time.time() - start < timeout:
        try:
            if pred():
                return True
        except (ftplib.all_errors, OSError):
            pass   # связь прихрамывает — просто ждём дальше
        time.sleep(5)
    print(f"⚠️  таймаут ожидания: {what}")
    return False


def main():
    try:
        _main()
    except KeyboardInterrupt:
        print("\nПока! Перезапусти, когда будешь готов: личность и метка сохранятся.")


def _main():
    ap = argparse.ArgumentParser(description="Участник выборов")
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--nick", default="")
    ap.add_argument("--key", default="elector_privkey.pem")
    args = ap.parse_args()

    _, store = _load_or_fetch_config(args.config)

    resumed = os.path.exists(args.key)
    if resumed:
        nick = args.nick or "Участник"
    else:
        nick = args.nick or input("Твой ник (виден только тебе): ").strip()

    e = ElectorEngine(store, nickname=nick, key_path=args.key)
    e.load_or_create_keys()     # ключ есть → та же метка, та же личность
    e.generate_mark()
    e.generate_mark2()
    print(f"Привет, {nick}!")
    print("Твоя метка (покажи регистратору, её же вставляешь в accept):")
    print(e.mark_1)

    if e.is_authorized():
        print("Твой ключ уже авторизован — продолжаем с того же места.")
    else:
        qr_text = e.register_begin()   # свежий запрос на подпись
        print(render_qr_terminal(qr_text))
        print("Покажи этот код регистратору, чтобы тебя допустили.")
        _wait_until(e.is_approved, "одобрения регистратора")
        print("✅ Ты в списке допущенных")
        _wait_until(e.try_fetch_signature, "подписи регистратора")
        print("✅ Регистратор подписал твой ключ")
        _wait_until(lambda: _try_authorize(e), "публикации твоего ключа")
        print("✅ Твой ключ авторизован")

    voted = e.find_my_ballot() is not None
    if voted:
        e.secret_key = e._derive_secret_key()
    submitted = e.secret_key_published()
    last_phase = e.phase()
    while True:
        try:
            ph = e.phase()
        except (ftplib.all_errors, OSError):
            # связь с FTP прихрамывает — не роняем участника, ждём и повторяем
            print("⚠️ Сервер не ответил — жду и повторяю…")
            time.sleep(5)
            continue
        if ph != last_phase:
            print(f"\n=== Фаза сменилась: {ph} ===")
            last_phase = ph
        if ph == "VOTING" and not voted:
            print("\nИдёт ГОЛОСОВАНИЕ. Кандидаты:")
            for c in e.candidates:
                print(f"  {c['id']}. {c['name']}")
            try:
                cid = int(input("Твой голос (номер): ").strip())
            except ValueError:
                print("Нужно ввести номер кандидата.")
                time.sleep(2)
                continue
            if not any(c["id"] == cid for c in e.candidates):
                print("Нет такого кандидата.")
                time.sleep(2)
                continue
            e.vote(cid)
            voted = True
            print("Бюллетень отправлен. Ждём фазы «Ключи»…")
        elif ph == "KEYS" and voted and not submitted:
            print("Голосование закрыто. Отдаём ключ расшифровки…")
            e.submit_secret_key()
            submitted = True
            print("✅ Ключ отправлен. Результат скоро появится на стене.")
        elif ph == "RESULT":
            print("Выборы завершены. Пересчитываем итог из публичных файлов…")
            try:
                from view import load_public_state, print_report
                print_report(load_public_state(store))
                print("Это независимый пересчёт — сверь со стеной.")
            except Exception as e:
                print("Не удалось пересчитать итог:", e)
                print("Запусти вручную: ./verify.py")
            break
        time.sleep(5)


if __name__ == "__main__":
    main()
