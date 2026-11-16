# Minimal host application around aiohttp-session (NaClCookieStorage) at a pinned commit.
# It speaks the endpoint contract of the SessTrace "profile" operation: /login, /profile, /logout.
# Usage: python3 aiohttp_session_host.py <path of the checked-out library> <port> <lifetime in seconds>
import hashlib, os, sys

lib, port, lifetime = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
sys.path.insert(0, lib)  # the library is imported from the checkout, as the phase 1 hosts require(lib)

from aiohttp import web  # noqa: E402
import aiohttp_session  # noqa: E402
from aiohttp_session import setup, get_session, new_session  # noqa: E402
from aiohttp_session.nacl_storage import NaClCookieStorage  # noqa: E402

init_file = os.path.abspath(aiohttp_session.__file__)
print("aiohttp_session file:", init_file, flush=True)
print("aiohttp_session/__init__.py sha256:", hashlib.sha256(open(init_file, "rb").read()).hexdigest(), flush=True)

# fixed test key, 32 bytes; it protects nothing outside this throw-away process
KEY = bytes.fromhex("d0d1db2409e90402c55772f6c92f71e265fb924ec19cfffac0efe84b071b5684")


async def login(request):
    user = request.query.get("user", "")
    if user not in ("alice", "bob"):
        return web.json_response({"error": "invalid_request"}, status=400)
    session = await new_session(request)
    session["user"] = user
    return web.json_response({"logged_in": True})


async def profile(request):
    session = await get_session(request)
    user = session.get("user")
    if not user:
        return web.json_response({"error": "no_session"}, status=401)
    return web.json_response({"sub": user, "rp": "RP1"})


async def logout(request):
    session = await get_session(request)
    session.invalidate()
    return web.json_response({"logged_out": True})


async def ready(request):
    return web.json_response({"ok": True})


app = web.Application()
setup(app, NaClCookieStorage(KEY, cookie_name="sid", max_age=lifetime))
app.router.add_get("/login", login)
app.router.add_get("/profile", profile)
app.router.add_get("/logout", logout)
app.router.add_get("/ready", ready)
print("READY", flush=True)
web.run_app(app, host="127.0.0.1", port=port)
