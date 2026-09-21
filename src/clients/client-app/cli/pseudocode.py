"""PSEUDOCODE: Ilk CLI adapter'i."""


def run_cli(config_path, profile_path=None):
    settings = load_settings(config_path, profile_path)
    app = build_client_application(settings)

    print("1) Send text")
    print("2) Send PDF")
    print("3) Establish key")
    print("4) Exit")

    choice = input("Select: ")
    if choice == "1":
        app.send_text(input("Message: "), receiver_id=ask_receiver())
    elif choice == "2":
        app.send_pdf(input("PDF path: "), receiver_id=ask_receiver())
    elif choice == "3":
        app.establish_session()
    elif choice == "4":
        return
