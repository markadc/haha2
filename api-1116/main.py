import argparse
from dataclasses import dataclass
import hashlib
import hmac
import html
import os
from pathlib import Path
import secrets
import tomllib
from urllib.parse import quote

from fastapi import Cookie, FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from pydantic import BaseModel
import uvicorn

BASE_DIR = Path(__file__).resolve().parent
PAGES_DIR = BASE_DIR / "pages"
CONFIG_PATH = BASE_DIR / "pages.toml"

ACCESS_KEY = os.getenv("SWX_ACCESS_KEY", "wsxg")
COOKIE_NAME = "swx_auth"
COOKIE_SECRET = os.getenv("SWX_COOKIE_SECRET") or secrets.token_hex(32)

app = FastAPI(title="SWX")


class VerifyRequest(BaseModel):
    key: str


@dataclass(frozen=True)
class PageEntry:
    page_id: str
    filename: str
    title: str


def _make_token(key: str) -> str:
    return hmac.new(COOKIE_SECRET.encode(), key.encode(), hashlib.sha256).hexdigest()


def _is_authenticated(token: str | None) -> bool:
    if not token:
        return False
    expected = _make_token(ACCESS_KEY)
    return secrets.compare_digest(token, expected)


def _load_pages() -> dict[str, PageEntry]:
    """Load page mappings from pages.toml on demand."""
    if not CONFIG_PATH.is_file():
        return {}
    with CONFIG_PATH.open("rb") as f:
        data = tomllib.load(f)
    raw_pages = data.get("pages", {})
    if not isinstance(raw_pages, dict):
        return {}

    pages: dict[str, PageEntry] = {}
    for page_id, spec in raw_pages.items():
        if isinstance(spec, str):
            filename = spec
            title = Path(filename).stem
        elif isinstance(spec, dict) and isinstance(spec.get("file"), str):
            filename = spec["file"]
            title = str(spec.get("title") or Path(filename).stem)
        else:
            continue
        pages[str(page_id)] = PageEntry(
            page_id=str(page_id),
            filename=filename,
            title=title,
        )
    return pages


def _resolve_page_path(filename: str) -> Path | None:
    """Resolve a page file safely within PAGES_DIR."""
    pages_root = PAGES_DIR.resolve()
    target = (pages_root / filename).resolve()
    if not target.is_relative_to(pages_root) or not target.is_file():
        return None
    return target


AUTH_PAGE_HTML = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>请输入访问密钥</title>
<style>
:root{
  --bg:#ffe3e8; --card:#fff8f9; --ink:#4a1226; --rose:#e0245e; --rose-ink:#fff; --soft:#ffc2d1; --muted:#8a5566;
}
@media (prefers-color-scheme:dark){
  :root{--bg:#2a0f1a;--card:#3a1624;--ink:#ffe8ee;--rose:#ff5c8a;--rose-ink:#2a0f1a;--soft:#6b2a42;--muted:#e3a6b8;color-scheme:dark}
}
*{box-sizing:border-box}
body{
  margin:0;min-height:100vh;background:var(--bg);color:var(--ink);
  font-family:"PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  display:flex;align-items:center;justify-content:center;padding:20px;
}
.backdrop{
  position:fixed;inset:0;background:rgba(0,0,0,.22);backdrop-filter:blur(4px);
  display:flex;align-items:center;justify-content:center;padding:20px;
}
.modal{
  width:100%;max-width:360px;background:var(--card);border:3px solid var(--soft);
  border-radius:24px;padding:28px 24px;text-align:center;
  box-shadow:0 16px 40px rgba(0,0,0,.15);
  animation:pop .2s ease-out;
}
@keyframes pop{from{transform:scale(.92);opacity:0}to{transform:scale(1);opacity:1}}
.icon{font-size:46px;line-height:1;margin-bottom:10px}
h1{font-size:22px;margin:0 0 8px;font-weight:600}
p{margin:0 0 18px;color:var(--muted);font-size:14px}
input{
  width:100%;padding:12px 14px;border-radius:14px;border:2px solid var(--soft);
  background:transparent;color:var(--ink);font-size:16px;outline:none;text-align:center;
}
input:focus{border-color:var(--rose)}
button{
  margin-top:14px;width:100%;padding:12px;border:0;border-radius:999px;
  background:var(--rose);color:var(--rose-ink);font-size:16px;font-weight:600;cursor:pointer;
}
button:disabled{opacity:.6;cursor:not-allowed}
.err{min-height:20px;margin-top:10px;color:var(--rose);font-size:13px}
</style>
</head>
<body>
<div class="backdrop">
  <form class="modal" id="form">
    <div class="icon">🔐</div>
    <h1>需要访问密钥</h1>
    <p>请输入密钥后继续访问</p>
    <input id="key" type="password" placeholder="请输入密钥" autocomplete="off" autofocus required>
    <button id="btn" type="submit">确认进入</button>
    <div class="err" id="err"></div>
  </form>
</div>
<script>
const form = document.getElementById('form');
const input = document.getElementById('key');
const btn = document.getElementById('btn');
const err = document.getElementById('err');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  err.textContent = '';
  btn.disabled = true;
  try {
    const res = await fetch('/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key: input.value.trim() }),
    });
    if (res.ok) {
      window.location.reload();
      return;
    }
    const data = await res.json().catch(() => ({}));
    err.textContent = data.detail || '密钥错误，请重试';
    input.select();
  } catch {
    err.textContent = '网络异常，请重试';
  } finally {
    btn.disabled = false;
  }
});
</script>
</body>
</html>
"""


def _render_index_html(pages: dict[str, PageEntry]) -> str:
    items = []
    for entry in pages.values():
        href = f"/swx/{quote(entry.page_id, safe='')}"
        title = html.escape(entry.title)
        pid = html.escape(entry.page_id)
        items.append(
            f'<a class="item" href="{href}">'
            f'<span class="title">{title}</span>'
            f'<span class="path">/swx/{pid}</span>'
            f"</a>"
        )
    list_html = (
        "\n".join(items)
        if items
        else '<p class="empty">暂无已配置页面，请检查 pages.toml</p>'
    )
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>页面导航</title>
<style>
:root{{
  --bg:#ffe3e8; --card:#fff8f9; --ink:#4a1226; --rose:#e0245e; --soft:#ffc2d1; --muted:#8a5566;
}}
@media (prefers-color-scheme:dark){{
  :root{{--bg:#2a0f1a;--card:#3a1624;--ink:#ffe8ee;--rose:#ff5c8a;--soft:#6b2a42;--muted:#e3a6b8;color-scheme:dark}}
}}
*{{box-sizing:border-box}}
body{{
  margin:0;min-height:100vh;background:var(--bg);color:var(--ink);
  font-family:"PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;
  display:flex;align-items:center;justify-content:center;padding:20px;
}}
.card{{
  width:100%;max-width:440px;background:var(--card);border:3px solid var(--soft);
  border-radius:26px;padding:28px 22px;box-shadow:0 16px 40px rgba(0,0,0,.1);
}}
h1{{margin:0 0 6px;font-size:24px;text-align:center}}
.sub{{margin:0 0 20px;color:var(--muted);font-size:14px;text-align:center}}
.list{{display:flex;flex-direction:column;gap:12px}}
.item{{
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:14px 16px;border-radius:16px;border:2px solid var(--soft);
  text-decoration:none;color:var(--ink);transition:transform .15s,border-color .15s;
}}
.item:hover{{transform:translateY(-2px);border-color:var(--rose)}}
.title{{font-size:17px;font-weight:600}}
.path{{font-size:13px;color:var(--muted);font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}
.empty{{text-align:center;color:var(--muted);margin:16px 0 4px}}
</style>
</head>
<body>
<main class="card">
  <h1>请选择要访问的页面</h1>
  <p class="sub">共 {len(pages)} 个已配置页面</p>
  <div class="list">
    {list_html}
  </div>
</main>
</body>
</html>
"""


@app.get("/", response_model=None)
def render_index(swx_auth: str | None = Cookie(default=None)) -> Response:
    """Serve the configured pages list if authenticated, otherwise show the access-key modal."""
    if not _is_authenticated(swx_auth):
        return HTMLResponse(AUTH_PAGE_HTML)
    return HTMLResponse(_render_index_html(_load_pages()))


@app.get("/swx/{page_id}", response_model=None)
def render_page(
    page_id: str,
    swx_auth: str | None = Cookie(default=None),
) -> Response:
    """Serve a configured HTML page under /swx/<id>."""
    if not _is_authenticated(swx_auth):
        return HTMLResponse(AUTH_PAGE_HTML)
    pages = _load_pages()
    entry = pages.get(page_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Page not found")
    page_path = _resolve_page_path(entry.filename)
    if page_path is None:
        raise HTTPException(status_code=404, detail="HTML file not found")
    return FileResponse(page_path, media_type="text/html; charset=utf-8")


@app.post("/verify")
def verify_key(payload: VerifyRequest) -> JSONResponse:
    """Verify the access key and set an HttpOnly auth cookie."""
    if not secrets.compare_digest(payload.key, ACCESS_KEY):
        raise HTTPException(status_code=401, detail="密钥错误，请重试")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(
        key=COOKIE_NAME,
        value=_make_token(ACCESS_KEY),
        httponly=True,
        samesite="lax",
    )
    return resp


@app.get("/health")
def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the SWX FastAPI server.")
    parser.add_argument(
        "--host",
        default=os.getenv("HOST", "127.0.0.1"),
        help="Bind host (default: HOST env var or 127.0.0.1)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=int(os.getenv("PORT", "8000")),
        help="Bind port (default: PORT env var or 8000)",
    )
    parser.add_argument(
        "--reload",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable auto-reload (default: enabled)",
    )
    args = parser.parse_args()
    uvicorn.run("main:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()
