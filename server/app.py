import os

import uvicorn
from fastapi.staticfiles import StaticFiles

from server.ui import create_app, register_ui


def build():
    application = create_app()
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
    application.mount("/static", StaticFiles(directory=static_dir), name="static")
    register_ui(application)
    return application


app = build()


def main():
    # ATOR_DEV_RELOAD=1 restarts the server when code/templates change so the
    # dashboard never serves stale routes during development.
    reload_enabled = os.environ.get("ATOR_DEV_RELOAD", "").strip().lower() in ("1", "true", "yes")
    uvicorn.run(
        "server.app:app",
        host=os.environ.get("ATOR_HOST", "0.0.0.0"),
        port=int(os.environ.get("ATOR_PORT", "8000")),
        reload=reload_enabled,
    )


if __name__ == "__main__":
    main()
