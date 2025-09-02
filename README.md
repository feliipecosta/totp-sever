# TOTP Server

This is a simple, self-hosted web application to display Time-Based One-Time Passwords (TOTP) for your two-factor authentication (2FA) accounts. It's designed to be a secure alternative to cloud-based 2FA applications.

The application stores your 2FA secrets in an encrypted file (`secrets.enc`) and requires a password to decrypt and display the codes.

## Features

-   **Secure**: Your 2FA secrets are encrypted using AES-256-GCM and can only be decrypted with your password.
-   **Self-hosted**: You have full control over your data.
-   **Simple**: The application is easy to set up and use.
-   **Real-time updates**: The codes are updated in real-time without needing to refresh the page.

## Setup

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/feliipecosta/totp-sever.git
    cd totp-server
    ```

2.  **Create `secrets.json`:**

    Create a file named `secrets.json` in the root of the project. This file will temporarily store your 2FA secrets in plaintext. You can use `secrets_sample.json` as a template.

    ```json
    [
        {
            "name": "Google",
            "secret": "YOUR_GOOGLE_SECRET"
        },
        {
            "name": "GitHub",
            "secret": "YOUR_GITHUB_SECRET"
        }
    ]
    ```

3.  **Encrypt your secrets:**

    The project includes a command-line tool to encrypt your `secrets.json` file.

    ```bash
    go run main.go --encrypt-secret secrets.json
    ```

    You will be prompted to enter a password. This password will be used to encrypt your secrets and will be required to unlock the web application.

    After running the command, a `secrets.enc` file will be created. You can now safely delete the `secrets.json` file.

4.  **Run the application:**

    You can run the application using Docker or by building it from source.

    **Using Docker:**

    ```bash
    docker build -t totp-server .
    docker run -p 3450:3450 -v $(pwd)/secrets.enc:/app/secrets.enc totp-server
    ```

    **Building from source:**

    ```bash
    go run main.go
    ```

## Usage

1.  Open your web browser and navigate to `http://localhost:3450`.
2.  Enter the password you used to encrypt your secrets.
3.  The application will display the TOTP codes for your accounts.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
