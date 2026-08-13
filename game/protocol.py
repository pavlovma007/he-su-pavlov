import base64
import hashlib
import json
import re
import time

import pyaes

import lib_blind
from sync import FtpStore

# --- папки и файлы на FTP ---
F_MARKS = "marks"
F_SIGN_REQUESTS = "sign-requests"
F_SIGN_RESULTS = "sign-results"
F_AUTHORIZED_KEYS = "authorized-keys"
F_BALLOTS = "ballots"
F_SECRET_KEYS = "secret-keys"
META_PUBKEY = "meta/pubkey.txt"
META_CANDIDATES = "meta/candidates.json"
META_PHASE_DIR = "meta/phase"

PHASES = ("REGISTRATION", "VOTING", "KEYS", "RESULT")
VALID_PHASES = set(PHASES)

TS_RE = re.compile(r"-(\d{14})-(\d+)\.json$")


def pretty_json(data) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2)


def pubkey_to_pem(pub) -> str:
    return lib_blind.export_public_key(pub).decode("ascii")


def pem_to_pubkey(pem_text):
    return lib_blind.import_public_key(pem_text.encode("ascii"))


def hash_of_pub_key(pub_key_obj) -> int:
    der = pub_key_obj.export_key(format="DER")
    return lib_blind.bytes_to_int(hashlib.sha256(der).digest())


def make_sign_request(mark, blinded) -> dict:
    return {"mark": int(mark), "blinded": int(blinded)}


def make_authorize_payload(pem_text, key_sign) -> dict:
    return {"public_key_pem": str(pem_text), "key_sign": int(key_sign)}


def make_ballot(mark_2, pem_text, ballot_enc_b64, ballot_sign) -> dict:
    return {"mark_2": int(mark_2), "public_key_pem": str(pem_text),
            "ballot_enc_b64": str(ballot_enc_b64), "ballot_sign": int(ballot_sign)}


def make_secret_key(mark_2, pem_text, secret_key_b64, key_sign) -> dict:
    return {"mark_2": int(mark_2), "public_key_pem": str(pem_text),
            "secret_key_b64": str(secret_key_b64), "key_sign": int(key_sign)}


def authorize_key_valid(auth, registrar_pub) -> bool:
    try:
        pem_text = auth["public_key_pem"]
        pub = pem_to_pubkey(pem_text)
        expected = hash_of_pub_key(pub)
        recovered = lib_blind.verify(int(auth["key_sign"]), registrar_pub)
        return recovered == expected
    except Exception:
        return False


def valid_authorized_pems(auth_list, registrar_pub) -> list:
    pems = [a["public_key_pem"] for a in auth_list if authorize_key_valid(a, registrar_pub)]
    seen, out = set(), []
    for p in pems:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def ballot_status(ballot, authorized_pems, registrar_pub):
    if ballot.get("public_key_pem") not in authorized_pems:
        return "НЕ УЧТЁН", "избиратель не зарегистрирован"
    try:
        ct = base64.b64decode(ballot["ballot_enc_b64"])
        expected = lib_blind.hash_message_to_int(ct)
        recovered = lib_blind.verify(int(ballot["ballot_sign"]),
                                     pem_to_pubkey(ballot["public_key_pem"]))
        if recovered != expected:
            return "НЕ УЧТЁН", "подпись неверна"
    except Exception:
        return "НЕ УЧТЁН", "подпись неверна"
    return "УЧТЁН", None


def decrypt_ballot(ballot, secret_key_b64) -> str:
    key = base64.b64decode(secret_key_b64)
    if len(key) not in (16, 24, 32):
        raise ValueError("неверная длина ключа")
    aes = pyaes.AESModeOfOperationCTR(key)
    plain = aes.decrypt(base64.b64decode(ballot["ballot_enc_b64"]))
    return plain.decode("utf-8")


def parse_ts(name) -> str:
    m = TS_RE.search(name or "")
    return m.group(1) if m else ""


def phase_history_from_names(names) -> list:
    entries = []
    for n in names:
        m = re.match(r"([A-Z]+)-(\d{14})-(\d+)\.json$", n or "")
        if m:
            entries.append({"phase": m.group(1), "ts": m.group(2), "rand": int(m.group(3))})
    return sorted(entries, key=lambda e: (e["ts"], e["rand"]))


def phase_at_ts(phase_history, ts_str) -> str:
    cur = "REGISTRATION"
    for e in phase_history:
        if e["ts"] <= ts_str:
            cur = e["phase"]
        else:
            break
    return cur


def current_phase(store) -> str:
    ph = phase_history_from_names(store.list_filenames(META_PHASE_DIR))
    return ph[-1]["phase"] if ph else "REGISTRATION"


def _name_for(candidates, cid):
    for c in candidates:
        if c["id"] == cid:
            return c["name"]
    return None


def compute_tally(ballots, secret_keys, authorized_pems, registrar_pub, phase_history, candidates):
    tally = {c["id"]: 0 for c in candidates}
    rows = []
    seen = set()
    ordered = sorted(ballots, key=lambda b: (parse_ts(b.get("_file", "")), b.get("_file", "")))
    for b in ordered:
        ts = parse_ts(b.get("_file", ""))
        mark_2 = b.get("mark_2")
        status, reason = ballot_status(b, authorized_pems, registrar_pub)
        if status == "УЧТЁН" and mark_2 in seen:
            status, reason = "НЕ УЧТЁН", "повторный бюллетень"
        if status == "УЧТЁН" and phase_at_ts(phase_history, ts) != "VOTING":
            status, reason = "НЕ УЧТЁН", "голосование уже было закрыто"
        row = {"mark_2": mark_2, "status": status, "reason": reason,
               "candidate_id": None, "candidate_name": None, "ts": ts}
        if status == "УЧТЁН":
            seen.add(mark_2)
            sk = next((s for s in secret_keys if s.get("mark_2") == mark_2), None)
            if sk is None:
                row["status"], row["reason"] = "УЧТЁН", "ожидает ключ расшифровки"
            else:
                cid = None
                try:
                    cid = int(decrypt_ballot(b, sk["secret_key_b64"]).strip())
                except Exception:
                    cid = None
                if cid is not None and cid in tally:
                    row["candidate_id"] = cid
                    row["candidate_name"] = _name_for(candidates, cid)
                    tally[cid] += 1
                else:
                    row["status"], row["reason"] = "НЕ УЧТЁН", "ключ не подходит к бюллетеню"
        rows.append(row)
    return {"tally": tally, "rows": rows}


def load_config(path="config.json") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def make_store(cfg) -> FtpStore:
    ftp = cfg["ftp"]
    return FtpStore(ftp["host"], ftp.get("port", 21), ftp["user"], ftp["password"],
                    ftp.get("base_path", ""))


def iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")
