# TOTP Server

This is a simple, self-hosted web application to display Time-Based One-Time Passwords (TOTP) for your two-factor authentication (2FA) accounts. It's designed to be a secure alternative to cloud-based 2FA applications.

The application stores your 2FA secrets in an encrypted file (`secrets.enc`) and requires a password to decrypt and display the codes.

## Features

-   **Secure**: Your 2FA secrets are encrypted using AES-256-GCM and can only be decrypted with your password.
-   **Self-hosted**: You have full control over your data.
-   **Simple**: The application is easy to set up and use.
-   **Real-time updates**: The codes are updated automatically every 15 seconds without needing to refresh the page.
-   **Session Management**: Smart session handling with manual refresh detection.
-   **Auto-timeout**: Sessions automatically expire after 3 minutes of inactivity for security.

## Security Features

### Session Management
- **Automatic Code Updates**: TOTP codes refresh automatically every 15 seconds without requiring re-authentication.
- **Manual Refresh Protection**: When you manually refresh the page (F5, Ctrl+R), you'll be required to enter your password again for security.
- **Session Isolation**: Each browser tab/window requires separate authentication.
- **Auto-timeout**: Sessions expire automatically after 2 minutes of inactivity.

### Encryption
- Secrets are encrypted using AES-256-GCM with scrypt key derivation
- Password-based encryption with salt for additional security
- Secrets are only decrypted in memory when needed

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

### Application Behavior

- **Automatic Updates**: Once authenticated, TOTP codes will refresh automatically every 15 seconds.
- **Manual Refresh**: If you manually refresh the page (F5 or Ctrl+R), you'll need to re-enter your password.
- **New Tabs**: Opening the application in a new tab will require authentication.
- **Session Timeout**: Sessions automatically expire after 2 minutes of inactivity for security.
- **Code Display**: Each account shows its name, current TOTP code, and a visual progress bar indicating time remaining.

## API Endpoints

- `GET /` - Main page (unlock screen or codes page depending on session state)
- `POST /unlock` - Authenticate and unlock secrets
- `GET /api/codes` - Get current TOTP codes (requires valid session token)

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
