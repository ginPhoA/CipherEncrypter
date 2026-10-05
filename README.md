# CipherForge

CipherForge is an educational website for trying file encryption with AES-CBC
or RSA. Encryption and decryption run in your browser, so the GitHub Pages
version works without a Python server. You can also run the project locally.

> **For education only.** CipherForge is a learning demo, not secure file
> storage. Use sample files only; never use confidential, sensitive, or
> irreplaceable files. The app has no professional key management, identity
> verification, user authentication, or cloud storage.

Access link: https://ginphoa.github.io/CipherEncrypter/

## What it does

- Encrypts and decrypts text and binary files with AES-CBC.
- Demonstrates RSA public and private keys with very small files.
- Generates downloadable RSA key pairs and accepts PEM key files.
- Processes files and keys in the browser with the built-in Web Crypto API;
  file contents and keys are not uploaded to CipherForge.
- Includes a Flask server and Python implementation for local use and API
  examples. The webpage uses its browser implementation on both GitHub Pages
  and localhost.

The hosted GitHub Pages app needs only a modern browser. For local use, Python
and the packages in `requirements.txt` run the Flask server. No Node.js or
frontend build step is needed.

## Encryption in plain language

Encryption scrambles file contents so they can only be recovered using the
right secret. The scrambled result is called **ciphertext**. Decryption changes
it back into the original file.

### AES-CBC: one passcode for a file

AES-CBC uses the same passcode for encryption and decryption. CipherForge uses
PBKDF2 to derive encryption keys from the passcode, AES-256-CBC to encrypt the
file, and a separate HMAC check to detect changes to the encrypted package. A
random salt helps derive a unique key, and a fresh initialization vector (IV)
starts each encryption with a different value. The passcode is never included
in the download, so keep it safe. The package also contains the original
filename and file type.

AES-CBC is included to teach encryption concepts. It is not a modern default for
new systems. The source file limit is 20 MiB. Encrypted files use the
`.aescbc` extension; decrypted downloads include `.decrypt` before the original
file extension.

### RSA: a public key and a private key

RSA uses a key pair. The **public key** encrypts a file, and the matching
**private key** decrypts it. You can share the public key; keep the private key
safe. CipherForge generates RSA-2048 keys and uses RSA-OAEP with SHA-256.
Keys are PEM files, a standard text format for cryptographic keys, inside a
downloadable ZIP archive.

This version encrypts file contents directly with RSA, so it accepts at most
190 bytes per file. Most photos and ordinary documents are too large. RSA is
included here to demonstrate public-key encryption, not as a general-purpose
file cipher. RSA downloads use `.rsaenc`. The package includes the original
filename and file type as readable metadata; those details are not encrypted.

## Run CipherForge locally

### Requirements

- Python 3.11 or later.
- A terminal: Terminal on macOS, or PowerShell/Windows Terminal on Windows.
- Internet access while installing the Python packages.
- A modern browser such as Chrome, Edge, Firefox, or Safari.

The Flask server provides the local webpage and API on `127.0.0.1`, so other
computers on your network cannot connect to it. The webpage itself performs
file operations in your browser.

### macOS

Open Terminal, change to the folder containing CipherForge, then run:

```sh
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python run.py
```

Open <http://127.0.0.1:5000> in your browser. Leave the Terminal window open
while using the app. Press **Ctrl+C** in that window when you are finished.

### Windows

Open PowerShell or Windows Terminal, change to the folder containing
CipherForge, then run:

```powershell
py -3.11 --version
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe run.py
```

Open <http://127.0.0.1:5000> in your browser. Leave the terminal window open
while using the app. Press **Ctrl+C** there to stop the server.

If Windows cannot find `py`, install Python 3.11 or later, then open a new
terminal and try again.

### If port 5000 is already in use

Start the app on another local port:

macOS:

```sh
PORT=5050 python run.py
```

Windows PowerShell:

```powershell
$env:PORT = "5050"
.\.venv\Scripts\python.exe run.py
```

Then open <http://127.0.0.1:5050>.

## Use CipherForge on GitHub Pages

The root `index.html` opens the interface stored in `templates/index.html`.
This makes the project page load the CipherForge webpage instead of rendering
the repository README at the site root.

GitHub Pages serves the static webpage but does not run Flask. CipherForge
performs its cryptographic operations in the browser instead, so the hosted
page can generate RSA keys and encrypt or decrypt files without a backend.
Use the HTTPS GitHub Pages URL in a modern browser; Web Crypto requires a
secure browser context. Files and keys stay on your device.

## Try a round trip

Use disposable, non-sensitive sample files: one small text file and one small
binary file. The RSA example must be no larger than 190 bytes.

### AES-CBC

1. Read the warning on the page, then choose **Encrypt** and **AES-CBC**.
2. Select a file, enter a passcode, confirm it, and choose **Encrypt file**.
3. Download the `.aescbc` file. Switch to **Decrypt**, select that package, and
   enter the same passcode.
4. Click **Download processed file** to save the recovered file. Repeat with a
   small binary file to see that binary contents are supported too.

### RSA

1. Choose **RSA**, then generate a key-pair ZIP. A passphrase for the private
   key is optional. Download and extract the ZIP, then keep the private key safe.
2. Choose a file no larger than 190 bytes, select the public PEM, and encrypt it.
3. Switch to **Decrypt**, select the `.rsaenc` file and its matching private
   PEM, enter the private-key passphrase if you set one, and decrypt.

## Project layout

```text
CipherForge/
├── app/
│   ├── __init__.py          Creates the Flask app and registers routes
│   ├── constants.py         File and key size limits
│   ├── routes.py            Page, key-generation, encrypt, and decrypt endpoints
│   ├── validators.py        Upload, passcode, and key validation
│   ├── storage.py           Bounded upload reading
│   └── services/
│       ├── aes_cbc_service.py  AES-CBC package creation and recovery
│       └── rsa_service.py      RSA key, package, and recovery functions
├── static/
│   ├── css/styles.css       Page styling and responsive layout
│   └── js/
│       ├── app.js           Form behavior and download flow
│       └── crypto.js        Browser AES, RSA, PEM, and package handling
├── templates/index.html     The single-page interface
├── index.html               Root redirect for GitHub Pages
├── tests/
│   ├── test_aes_cbc_service.py
│   ├── test_rsa_service.py
│   └── test_routes.py       API and download behavior tests
├── instance/                Flask instance folder; runtime files are ignored
├── .github/workflows/
│   └── actions.yml          Automated repository checks
├── requirements.txt         Packages needed to run the app
├── requirements-dev.txt     Extra packages for tests and lint checks
├── pyproject.toml           Python and test/lint configuration
├── LICENSE                  Project license
├── .gitignore               Keeps local environments and key files out of Git
├── run.py                   Starts the local server
├── ProjectStructure.md      Archive of the previous detailed README
└── README.md                Project overview and setup guide
```

The webpage is in `templates/`, with its styles and browser code in `static/`.
`static/js/crypto.js` handles browser-side file processing. The Python services
in `app/` provide the local Flask API implementation and are covered by the
Python test suite. The root `index.html` forwards GitHub Pages visitors to the
webpage under `templates/`.

## Developer checks

GitHub Actions runs these checks on every push and pull request, using Python
3.11 (the project's minimum) and 3.14. It installs the development dependencies,
runs the complete test suite, checks Python lint rules, and checks formatting.
You can run the same checks locally after installing the development
dependencies. On macOS, activate `.venv` first if you opened a new terminal.

macOS:

```sh
python -m pip install -r requirements-dev.txt
python -m pytest
python -m ruff check .
python -m ruff format --check .
```

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
```

Pytest discovers every `test_*.py` file under `tests/`, so tests for a new
algorithm are included automatically. When adding one, add service tests for
known examples, encode/decode round trips, and invalid input, plus route tests
if it is exposed through the website. Keep the AES-CBC and RSA tests in place:
they run on every change and catch regressions in the existing workflows.

For example, substitution-cipher tests should check a known plaintext/ciphertext
pair, reject keys that are not 26 unique letters, preserve case and punctuation,
and exercise its route if a route is added. The workflow can only verify behavior
that has tests; the new algorithm needs those tests to provide a meaningful
regression check.

## Current scope

AES-CBC and direct RSA workflows are implemented. A substitution cipher is a
possible future educational feature; it is not in this version. CipherForge is
for local use and is not publicly hosted.

See [LICENSE](LICENSE) for the project license.
