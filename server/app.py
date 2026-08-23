import uvicorn

from server.ui import create_app, register_ui


def build():
    application = create_app()
    register_ui(application)
    return application


app = build()


def main():
    uvicorn.run("server.app:app", host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
