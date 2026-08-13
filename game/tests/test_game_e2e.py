import base64
import os
import time

import pyaes

import lib_blind
import protocol as pr
from agency import AgencyEngine
from elector import ElectorEngine
from view import load_public_state

CANDIDATES = [
    {"id": 1, "name": "Кандидат №1"},
    {"id": 2, "name": "Кандидат №2"},
    {"id": 3, "name": "Против всех"},
]


def _sleep(sec=1.1):
    time.sleep(sec)


def test_full_game(store, tmp_path):
    agency = AgencyEngine(store, CANDIDATES, election="Тестовые выборы",
                          key_path=str(tmp_path / "registrar.pem"),
                          batch_size=3, batch_seconds=1)
    agency.start()
    assert pr.current_phase(store) == "REGISTRATION"

    # --- регистрация двух участников ---
    voters = []
    for nick in ("Кот", "Пёс"):
        e = ElectorEngine(store, nickname=nick, key_path=str(tmp_path / f"{nick}.pem"))
        e.generate_mark()
        e.generate_mark2()
        e.generate_keys()
        e.register_begin()
        voters.append(e)

    _sleep()
    agency.approve_mark(voters[0].mark_1)
    agency.approve_mark(voters[1].mark_1)
    # одобрения не появляются мгновенно — это часть приватности
    assert store.list_folder(pr.F_MARKS) == []
    agency.flush_pending()
    assert set(agency.public_approved_marks()) == {voters[0].mark_1, voters[1].mark_1}

    _sleep()
    assert agency.process_once() == 2          # оба слепых запроса подписаны
    agency.flush_pending()
    for e in voters:
        assert e.try_fetch_signature()
        e.try_authorize()
    assert all(e.is_authorized() for e in voters)

    # --- незарегистрированный: метку никто не одобрил ---
    rogue = ElectorEngine(store, nickname="Чужой", key_path=str(tmp_path / "rogue.pem"))
    rogue.generate_mark(); rogue.generate_mark2(); rogue.generate_keys()
    rogue.register_begin()
    _sleep()
    assert agency.process_once() == 0          # запрос неодобренной метки не подписан

    # --- голосование ---
    _sleep()
    agency.set_phase("VOTING")
    assert pr.current_phase(store) == "VOTING"
    voters[0].vote(1)
    voters[1].vote(2)
    rogue.vote(1)                              # появится, но не зачтётся

    # повторный бюллетень от той же метки (после паузы — чтобы метки времени различались)
    _sleep()
    aes2 = pyaes.AESModeOfOperationCTR(os.urandom(16))
    ct2 = aes2.encrypt(b"3")
    ct2_b64 = base64.b64encode(ct2).decode("ascii")
    sig2 = lib_blind.signature(ct2, voters[0].private_key)
    dup = pr.make_ballot(voters[0].mark_2, pr.pubkey_to_pem(voters[0].public_key),
                         ct2_b64, sig2)
    store.upload_json(pr.F_BALLOTS, str(voters[0].mark_2), dup)

    # бюллетень с испорченной подписью от зарегистрированного ключа
    aes3 = pyaes.AESModeOfOperationCTR(os.urandom(16))
    ct3 = aes3.encrypt(b"2")
    ct3_b64 = base64.b64encode(ct3).decode("ascii")
    bad_sign = lib_blind.signature(ct3, voters[0].private_key) + 1
    bad = pr.make_ballot(999001, pr.pubkey_to_pem(voters[0].public_key), ct3_b64, bad_sign)
    store.upload_json(pr.F_BALLOTS, "999001", bad)

    # --- фаза КЛЮЧИ ---
    _sleep()
    agency.set_phase("KEYS")
    voters[0].submit_secret_key()
    voters[1].submit_secret_key()
    rogue.submit_secret_key()

    # опоздавший: регистрируется и голосует ПОСЛЕ закрытия голосования
    late = ElectorEngine(store, nickname="Опоздавший", key_path=str(tmp_path / "late.pem"))
    late.generate_mark(); late.generate_mark2(); late.generate_keys()
    late.register_begin()
    _sleep()
    agency.approve_mark(late.mark_1)
    agency.flush_pending()
    _sleep()
    assert agency.process_once() >= 1
    agency.flush_pending()
    assert late.try_fetch_signature()
    late.try_authorize()
    late.vote(3)                               # подан в фазе KEYS → не зачтётся

    # --- итог ---
    _sleep()
    agency.set_phase("RESULT")
    state = load_public_state(store)
    assert state["phase"] == "RESULT"

    # ВАЖНО (правка контроллера): dict-компрехеншен {r["mark_2"]: r} оставил бы
    # ПОСЛЕДНИЙ ряд по mark_2 — у Кота есть повторный бюллетень, и он бы перекрыл
    # УЧТЁННЫЙ. setdefault берёт первый (зарегистрированный, он раньше по ts).
    by = {}
    for r in state["rows"]:
        by.setdefault(r["mark_2"], r)
    assert by[voters[0].mark_2]["status"] == "УЧТЁН"
    assert by[voters[0].mark_2]["candidate_id"] == 1
    assert by[voters[1].mark_2]["status"] == "УЧТЁН"
    assert by[voters[1].mark_2]["candidate_id"] == 2

    assert by[rogue.mark_2]["status"] == "НЕ УЧТЁН"
    assert "зарегистрирован" in by[rogue.mark_2]["reason"]

    assert by[999001]["status"] == "НЕ УЧТЁН"
    assert "подпись" in by[999001]["reason"]

    assert by[late.mark_2]["status"] == "НЕ УЧТЁН"
    assert "закрыто" in by[late.mark_2]["reason"]

    # повторный бюллетень (та же mark_2, что у Кота) — не зачтён
    dup_row = next(r for r in state["rows"]
                   if r["mark_2"] == voters[0].mark_2 and r["candidate_id"] is None)
    assert dup_row["status"] == "НЕ УЧТЁН"
    assert "повтор" in dup_row["reason"]

    assert state["tally"] == {1: 1, 2: 1, 3: 0}
