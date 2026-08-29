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
    uvicorn.run("server.app:app", host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
