import base64
import hashlib
import json
import os

import protocol as pr
from agency import AgencyEngine
from elector import ElectorEngine, _load_or_fetch_config

CANDIDATES = [{"id": 1, "name": "Кандидат №1"}, {"id": 2, "name": "Кандидат №2"}]


def test_marks_not_derived_from_public_key(store, tmp_path):
    """Метки - случайные имена, не выводимые из открытого ключа: регистратор,
    видевший метку, не может вычислить по ней ключ (см. elliptic-voting.md, 5.1)."""
    agency = AgencyEngine(store, CANDIDATES, key_path=str(tmp_path / "reg.pem"))
    agency.start()   # публикует meta, которое читает ElectorEngine
    e = ElectorEngine(store, nickname="Кот", key_path=str(tmp_path / "cat.pem"))
    e.generate_keys()
    e.generate_mark()
    e.generate_mark2()
    der = e.public_key.export_key(format="DER")
    old_style_1 = int.from_bytes(hashlib.sha256(der + b"mark-1").digest(), "big") % 2 ** 63
    old_style_2 = int.from_bytes(hashlib.sha256(der + b"mark-2").digest(), "big") % 2 ** 63
    assert e.mark_1 != old_style_1
    assert e.mark_2 != old_style_2
    # свежие случайные метки: у разных избирателей они разные
    other = ElectorEngine(store, nickname="Пёс", key_path=str(tmp_path / "dog.pem"))
    other.generate_keys()
    other.generate_mark()
    other.generate_mark2()
    assert len({e.mark_1, other.mark_1, e.mark_2, other.mark_2}) == 4


def test_registration_and_authorization(store, tmp_path):
    agency = AgencyEngine(store, CANDIDATES, key_path=str(tmp_path / "reg.pem"),
                          batch_size=3)
    agency.start()

    e = ElectorEngine(store, nickname="Кот", key_path=str(tmp_path / "cat.pem"))
    e.generate_mark()
    e.generate_mark2()
    e.generate_keys()
    qr_text = e.register_begin()
    assert qr_text == pr.pretty_json({"mark": e.mark_1})
    assert not e.is_approved()

    agency.approve_mark(e.mark_1)
    agency.flush_pending()
    assert e.is_approved()

    assert agency.process_once() == 1
    agency.flush_pending()
    assert e.try_fetch_signature()
    e.try_authorize()
    assert e.is_authorized()


def test_vote_and_submit_secret_key(store, tmp_path):
    agency = AgencyEngine(store, CANDIDATES, key_path=str(tmp_path / "reg.pem"),
                          batch_size=3)
    agency.start()
    e = ElectorEngine(store, nickname="Пёс", key_path=str(tmp_path / "dog.pem"))
    e.generate_mark(); e.generate_mark2(); e.generate_keys()
    e.register_begin()
    agency.approve_mark(e.mark_1)
    agency.flush_pending()
    agency.process_once()
    agency.flush_pending()
    e.try_fetch_signature()
    e.try_authorize()

    agency.set_phase("VOTING")
    e.vote(1)
    assert e.ballot_published()
    agency.set_phase("KEYS")
    e.submit_secret_key()

    keys = store.list_folder(pr.F_SECRET_KEYS)
    assert len(keys) == 1
    # ключ расшифровывает собственный бюллетень в номер кандидата
    ballot = store.list_folder(pr.F_BALLOTS)[0]
    assert pr.decrypt_ballot(ballot, keys[0]["secret_key_b64"]) == "1"


def test_restart_keeps_identity_via_state_file(store, tmp_path):
    """Перезапуск - та же метка и тот же ключ шифрования: случайные метки
    переживают перезапуск через state-файл рядом с ключом."""
    agency = AgencyEngine(store, CANDIDATES, key_path=str(tmp_path / "reg.pem"))
    agency.start()   # публикует meta: ключ регистратора и список кандидатов

    key_path = str(tmp_path / "cat.pem")

    first = ElectorEngine(store, nickname="Кот", key_path=key_path)
    first.generate_keys()
    first.generate_mark()
    first.generate_mark2()
    first.vote(1)

    # «перезапуск»: новый процесс, тот же файл ключа + state-файл с метками
    again = ElectorEngine(store, nickname="Участник", key_path=key_path)
    again.load_or_create_keys()
    again.generate_mark()
    again.generate_mark2()

    assert again.mark_1 == first.mark_1
    assert again.mark_2 == first.mark_2
    assert again.mark_auth == first.mark_auth
    assert again._derive_secret_key() == first.secret_key  # ключ расшифровки не потерян
    # метки живут в state-файле рядом с ключом (личность - в ключе + метках)
    assert set(os.listdir(tmp_path)) == {"reg.pem", "cat.pem", "cat_state.json"}


def _test_config(ftp_server, store, **extra):
    cfg = {"ftp": {"host": ftp_server["host"], "port": ftp_server["port"],
                   "user": ftp_server["user"], "password": ftp_server["password"],
                   "base_path": store.base_path}}
    cfg.update(extra)
    return cfg


def test_load_or_fetch_config_prefers_server(store, ftp_server, tmp_path):
    """На сервере есть config.json (его публикует агентство) - берём его,
    локальный файл перезаписывается."""
    server_cfg = _test_config(ftp_server, store, election="Тема с сервера")
    store.upload_text("config.json", json.dumps(server_cfg, ensure_ascii=False))

    local = tmp_path / "config.json"
    local.write_text(json.dumps(_test_config(ftp_server, store, election="Тема локальная"),
                                ensure_ascii=False), encoding="utf-8")

    cfg, st = _load_or_fetch_config(str(local))

    assert cfg["election"] == "Тема с сервера"          # сервер главнее
    assert json.loads(local.read_text(encoding="utf-8"))["election"] == "Тема с сервера"
    assert st is not None


def test_load_or_fetch_config_falls_back_to_local(store, ftp_server, tmp_path):
    """Сервер недоступен или config.json ещё не опубликован - работаем с локальным."""
    local_cfg = _test_config(ftp_server, store, election="Тема локальная")
    local = tmp_path / "config.json"
    local.write_text(json.dumps(local_cfg, ensure_ascii=False), encoding="utf-8")

    cfg, st = _load_or_fetch_config(str(local))

    assert cfg["election"] == "Тема локальная"
