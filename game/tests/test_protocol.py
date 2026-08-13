import base64
import os
import time

import pyaes

import lib_blind
import protocol as pr


def _registered_pair():
    """Возвращает (registrar_pub, elector_pub, elector_priv, key_sign)."""
    reg_pub, reg_priv = lib_blind.keygen(2048)
    pub, priv = lib_blind.keygen(2048)
    pub_der = pub.export_key(format="DER")
    blinded, r = lib_blind.blind(pub_der, reg_pub)
    sig = pow(blinded, reg_priv.d, reg_priv.n)
    key_sign = lib_blind.unblind(sig, r, reg_pub)
    return reg_pub, pub, priv, key_sign


def test_authorize_key_valid():
    reg_pub, pub, _priv, key_sign = _registered_pair()
    pem = pr.pubkey_to_pem(pub)
    auth = pr.make_authorize_payload(pem, key_sign)
    assert pr.authorize_key_valid(auth, reg_pub)
    bad = dict(auth)
    bad["key_sign"] = int(auth["key_sign"]) + 1
    assert not pr.authorize_key_valid(bad, reg_pub)


def _make_ballot(pub, priv, candidate_id):
    sk = os.urandom(16)
    aes = pyaes.AESModeOfOperationCTR(sk)
    ct = aes.encrypt(str(candidate_id).encode("utf-8"))
    ct_b64 = base64.b64encode(ct).decode("ascii")
    sig = lib_blind.signature(ct, priv)
    return pr.make_ballot(123, pr.pubkey_to_pem(pub), ct_b64, sig), sk


def test_ballot_status_unregistered():
    reg_pub, pub, priv, _ = _registered_pair()
    ballot, _ = _make_ballot(pub, priv, 1)
    status, reason = pr.ballot_status(ballot, [], reg_pub)
    assert status == "НЕ УЧТЁН"
    assert "зарегистрирован" in reason


def test_ballot_status_bad_signature():
    reg_pub, pub, priv, _ = _registered_pair()
    ballot, _ = _make_ballot(pub, priv, 1)
    ballot["ballot_sign"] = int(ballot["ballot_sign"]) + 1
    status, reason = pr.ballot_status(ballot, [pr.pubkey_to_pem(pub)], reg_pub)
    assert status == "НЕ УЧТЁН"
    assert "подпись" in reason


def test_ballot_status_ok():
    reg_pub, pub, priv, _ = _registered_pair()
    ballot, _ = _make_ballot(pub, priv, 1)
    status, reason = pr.ballot_status(ballot, [pr.pubkey_to_pem(pub)], reg_pub)
    assert status == "УЧТЁН"
    assert reason is None


def test_decrypt_ballot():
    sk = os.urandom(16)
    aes = pyaes.AESModeOfOperationCTR(sk)
    ct = aes.encrypt(b"2")
    ct_b64 = base64.b64encode(ct).decode("ascii")
    ballot = pr.make_ballot(1, "PEM", ct_b64, 0)
    assert pr.decrypt_ballot(ballot, base64.b64encode(sk).decode("ascii")) == "2"


def test_phase_history_and_phase_at():
    names = [
        "REGISTRATION-20260808110000-1111.json",
        "VOTING-20260808120000-2222.json",
        "KEYS-20260808130000-3333.json",
    ]
    ph = pr.phase_history_from_names(names)
    assert [e["phase"] for e in ph] == ["REGISTRATION", "VOTING", "KEYS"]
    assert pr.phase_at_ts(ph, "20260808123000") == "VOTING"
    assert pr.phase_at_ts(ph, "20260808113000") == "REGISTRATION"
    assert pr.phase_at_ts(ph, "20260808133000") == "KEYS"


def test_current_phase(store):
    assert pr.current_phase(store) == "REGISTRATION"   # ничего нет → регистрация
    store.upload_json(pr.META_PHASE_DIR, "REGISTRATION", {"phase": "REGISTRATION"})
    time.sleep(1.1)
    store.upload_json(pr.META_PHASE_DIR, "VOTING", {"phase": "VOTING"})
    assert pr.current_phase(store) == "VOTING"


def test_compute_tally():
    reg_pub, pub, priv, _ = _registered_pair()
    pem = pr.pubkey_to_pem(pub)
    ballot, sk = _make_ballot(pub, priv, 1)
    ballot["_file"] = "ballots/123-20260808120010-0001.json"
    ballots = [ballot]
    secret_keys = [{
        "mark_2": 123,
        "secret_key_b64": base64.b64encode(sk).decode("ascii"),
    }]
    ph = [
        {"phase": "REGISTRATION", "ts": "20260808110000", "rand": 1},
        {"phase": "VOTING", "ts": "20260808120000", "rand": 2},
    ]
    candidates = [{"id": 1, "name": "Кандидат №1"}, {"id": 2, "name": "Кандидат №2"}]
    result = pr.compute_tally(ballots, secret_keys, [pem], reg_pub, ph, candidates)
    assert result["tally"] == {1: 1, 2: 0}
    assert result["rows"][0]["status"] == "УЧТЁН"
    assert result["rows"][0]["candidate_id"] == 1
