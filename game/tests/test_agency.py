import time

import protocol as pr
from agency import AgencyEngine, parse_accept

CANDIDATES = [
    {"id": 1, "name": "Кандидат №1"},
    {"id": 2, "name": "Кандидат №2"},
    {"id": 3, "name": "Против всех"},
]


def test_start_publishes_meta(store, tmp_path):
    a = AgencyEngine(store, CANDIDATES, key_path=str(tmp_path / "reg.pem"))
    a.start()
    assert store.exists(pr.META_PUBKEY)
    assert store.exists(pr.META_CANDIDATES)
    assert a.phase() == "REGISTRATION"


def test_start_publishes_config_to_server(store, tmp_path):
    """Агентство кладёт свой config.json на сервер - участники берут его оттуда."""
    a = AgencyEngine(store, CANDIDATES, key_path=str(tmp_path / "reg.pem"))
    cfg_file = tmp_path / "config.json"
    cfg_file.write_text('{"election": "Моя тема выборов"}', encoding="utf-8")
    a.start(config_path=str(cfg_file))
    assert store.exists("config.json")
    assert '"Моя тема выборов"' in store.read_text("config.json")


def test_approve_is_batched_not_immediate(store, tmp_path):
    a = AgencyEngine(store, CANDIDATES, key_path=str(tmp_path / "reg.pem"),
                     batch_size=3)
    a.start()
    a.approve_mark(17)
    a.approve_mark(42)
    # одобрения ещё не на FTP - приватность: нельзя связать «вышел» и «файл появился»
    assert store.list_folder(pr.F_MARKS) == []
    a.flush_pending()
    assert a.public_approved_marks() == [17, 42]


def test_process_once_signs_only_approved(store, tmp_path):
    a = AgencyEngine(store, CANDIDATES, key_path=str(tmp_path / "reg.pem"),
                     batch_size=3)
    a.start()
    a.approve_mark(17)
    a.flush_pending()
    store.upload_json(pr.F_SIGN_REQUESTS, "17", pr.make_sign_request(17, 123456789))
    store.upload_json(pr.F_SIGN_REQUESTS, "99", pr.make_sign_request(99, 987654321))  # не одобрена
    assert a.process_once() == 1          # подписывается только метка 17
    a.flush_pending()
    results = store.list_folder(pr.F_SIGN_RESULTS)
    assert len(results) == 1
    assert results[0]["mark"] == 17
    assert results[0]["blinded"] == 123456789


def test_set_phase_and_current(store, tmp_path):
    a = AgencyEngine(store, CANDIDATES, key_path=str(tmp_path / "reg.pem"))
    a.start()
    time.sleep(1.1)   # фазы пишутся в одну секунду - гарантируем разные ts для детерминированной сортировки
    a.set_phase("VOTING")
    assert a.phase() == "VOTING"


def test_parse_accept_tolerates_messy_paste():
    mark = 5653436965835586232
    assert parse_accept(f"accept {mark}") == mark
    assert parse_accept(f"accept {mark}\n") == mark          # копия Termux с переводом строки
    assert parse_accept(f"accept  {mark} ") == mark          # лишние пробелы
    assert parse_accept(f"Привет, чел! Твоя метка: {mark}") == mark  # выделил всю строку
    assert parse_accept(f"accept  Твоя метка:\n{mark}") == mark      # перенос внутри числа
    assert parse_accept("accept abc") is None                # нет цифр
    assert parse_accept("accept") is None                    # нет метки вообще
