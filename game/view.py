import json
import os

import protocol as pr
import lessons


def load_public_state(store):
    meta = json.loads(store.read_text(pr.META_CANDIDATES))
    registrar_pub = pr.pem_to_pubkey(store.read_text(pr.META_PUBKEY))
    ph = pr.phase_history_from_names(store.list_filenames(pr.META_PHASE_DIR))
    phase = ph[-1]["phase"] if ph else "REGISTRATION"
    auth_list = store.list_folder(pr.F_AUTHORIZED_KEYS)
    valid_auth = [a for a in auth_list if pr.authorize_key_valid(a, registrar_pub)]
    authorized = pr.valid_authorized_pems(auth_list, registrar_pub)
    ballots = store.list_folder(pr.F_BALLOTS)
    secret_keys = store.list_folder(pr.F_SECRET_KEYS)
    result = pr.compute_tally(ballots, secret_keys, authorized, registrar_pub,
                              ph, meta["candidates"])
    approved_marks = sorted(int(m["mark"]) for m in store.list_folder(pr.F_MARKS))
    return {
        "election": meta["election"],
        "candidates": meta["candidates"],
        "phase": phase,
        "phase_history": ph,
        "approved_marks": approved_marks,
        "authorized_marks": _parse_authorized_marks(valid_auth),
        "authorized_count": len(authorized),
        "rows": result["rows"],
        "tally": result["tally"],
        "secret_keys_count": len(secret_keys),
        "secret_keys_marks": sorted(int(s["mark_2"]) for s in secret_keys),
        "lessons": lessons.PHASE_LESSONS.get(phase, []),
    }


def _esc(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _parse_authorized_marks(valid_auth):
    out = []
    for a in valid_auth:
        try:
            out.append(int(os.path.basename(a["_file"]).split("-")[0]))
        except (ValueError, IndexError):
            pass
    out.sort()
    return out


def render_wall_html(state, generated_at=None) -> str:
    # страница открывается по ftp:// или из файла - без внешних ресурсов,
    # обновляется сама через JS каждые 7 секунд
    lines = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<title>Выборы</title><style>",
        "body{font-family:sans-serif;font-size:22px;margin:20px}",
        ".big{font-size:48px;font-weight:bold}",
        ".ok{color:#0a0}.no{color:#c00}",
        "table{border-collapse:collapse;width:100%}",
        "td,th{border:1px solid #888;padding:6px 10px;text-align:left}",
        "</style>",
        "<script>setTimeout(function(){location.reload();}, 7000);</script>",
        "</head><body>",
        f"<div class='big'>🗳️ {_esc(state['election'])}</div>",
        f"<div>Фаза: <b>{_esc(state['phase'])}</b></div>",
        (f"<div>Допущено меток: {len(state['approved_marks'])} · "
         f"Авторизованных ключей: {state['authorized_count']} · "
         f"Бюллетеней: {len(state['rows'])} · "
         f"Ключей расшифровки: {state['secret_keys_count']}</div>"),
        f"<div><i>Страница обновлена: {_esc(generated_at)} · автообновление каждые 7 секунд</i></div>",
        "<h2>Списки</h2>",
        (f"<div><b>Допущенные метки:</b> "
         f"{', '.join(map(str, state['approved_marks'])) or '-'}</div>"),
        (f"<div><b>Авторизованные ключи (метки):</b> "
         f"{', '.join(map(str, state['authorized_marks'])) or '-'}</div>"),
        (f"<div><b>Ключи расшифровки (mark_2):</b> "
         f"{', '.join(map(str, state['secret_keys_marks'])) or '-'}</div>"),
        "<h2>Итог</h2><table><tr><th>Кандидат</th><th>Голосов</th></tr>",
    ]
    for c in state["candidates"]:
        lines.append(f"<tr><td>{_esc(c['name'])}</td><td>{state['tally'].get(c['id'], 0)}</td></tr>")
    lines.append("</table>")
    lines.append("<h2>Бюллетени</h2><table><tr><th>mark_2</th><th>Статус</th><th>Причина</th><th>Кандидат</th></tr>")
    for r in state["rows"]:
        cls = "ok" if r["status"] == "УЧТЁН" else "no"
        cand = _esc(r["candidate_name"]) if r["candidate_name"] else "-"
        reason = _esc(r["reason"]) if r["reason"] else ""
        lines.append(f"<tr><td>{_esc(str(r['mark_2']))}</td><td class='{cls}'>{_esc(r['status'])}</td>"
                     f"<td>{reason}</td><td>{cand}</td></tr>")
    lines.append("</table>")
    lines.append("<h2>Почему так устроено</h2>")
    for q, a in state["lessons"]:
        lines.append(f"<p><b>❓ {_esc(q)}</b><br>{_esc(a)}</p>")
    lines.append("</body></html>")
    return "\n".join(lines)


def publish_wall(store, generated_at=None) -> str:
    """Вычисляет страницу стены из публичных файлов и заливает её в meta/index.html.

    meta/index.html - единственный перезаписываемый файл («живой экран»);
    все документы рекорда остаются append-only.
    """
    if generated_at is None:
        generated_at = pr.iso_now()
    state = load_public_state(store)
    html = render_wall_html(state, generated_at=generated_at)
    store.upload_text("meta/index.html", html)
    return html


def print_report(state) -> None:
    print("=" * 50)
    print(state["election"], "| фаза:", state["phase"])
    print("Меток допущено:", len(state["approved_marks"]))
    print("Авторизованных ключей:", state["authorized_count"])
    print("Бюллетеней:", len(state["rows"]), "· ключей расшифровки:", state["secret_keys_count"])
    print()
    for r in state["rows"]:
        reason = f" - {r['reason']}" if r["reason"] else ""
        cand = f" → {r['candidate_name']}" if r["candidate_name"] else ""
        print(f"  {r['mark_2']}: {r['status']}{reason}{cand}")
    print()
    print("ИТОГ:")
    for c in state["candidates"]:
        print(f"  {c['name']}: {state['tally'].get(c['id'], 0)}")
