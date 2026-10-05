# CipherForge

## Repository status

The interactive frontend and local Flask AES-CBC workflow are implemented.
The next algorithm milestone is **Day 2: RSA**. The substitution cipher and
public hosting remain later work.

The development configuration provides a repeatable local setup, test
configuration, linting rules, and safeguards against committing cryptographic
material or runtime uploads. No generated keys, passwords, uploaded files,
encrypted packages, or decrypted files belong in this repository.

## Local development setup

CipherForge targets Python 3.11 or later. Create an isolated environment and
install the development dependencies before beginning implementation:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

During implementation, use these checks before considering a change ready:

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
```

Start the application locally with:

```bash
python run.py
```

Then open <http://127.0.0.1:5000>. The server binds only to `127.0.0.1`.

## Static frontend preview

Open `templates/index.html` directly in a browser to preview the interface.
Operation switching, file selection, drag-and-drop, and client-side validation
work without a server. Encryption and decryption require the Flask server; when
the page is opened directly, submitting explains how to start it.

## Development plan

CipherForge is a small local webpage for demonstrating file encryption with two cryptographic algorithms:

1. RSA
2. AES-CBC

The first version should be achievable in approximately one to three focused days. The application will run locally first. A future public deployment may be considered after the local workflow is stable and has been reviewed.

`Crypt_Algorithm` is a separate reference repository. It is not the main project and must not be changed as part of CipherForge development. Its Python exercises provide context for how the RSA and AES-CBC backend services may be structured.

## Educational-purpose rule

All of CipherForge is for educational purposes only.

The project must display this disclaimer clearly in the webpage and documentation. It must explain that:

- The application is a learning and demonstration tool, not a secure file-storage service.
- Users must not upload confidential, sensitive, or irreplaceable files.
- The AES-CBC workflow is included to demonstrate cryptographic concepts and should not be treated as a modern default for new systems.
- RSA has strict message-size limits and is not a general-purpose large-file cipher when used directly.
- The application does not provide professional key management, identity verification, authentication, or secure cloud storage.
- The future substitution cipher is intentionally weak and will also be educational only.

The project may be presented on a resume or LinkedIn as an educational cryptography and web-development demonstration, but it must not imply that it is suitable for protecting real-world secrets.

## Scope and priorities

### First release: required

- Local Flask/Python web server.
- Single-page HTML/CSS/JavaScript interface.
- Encrypt and decrypt operation selection.
- RSA option with key generation, key import, encryption, and decryption.
- AES-CBC option with password-based encryption and decryption.
- File upload and download handling.
- Validation and clear user-facing errors.
- Basic automated tests for both algorithms.
- A visible educational disclaimer.

### Later addition: substitution cipher

The substitution cipher should be added only after the RSA and AES-CBC workflows, tests, and interface are complete. It should be treated as a separate educational feature rather than a requirement for the first release.

The later substitution feature can be limited to UTF-8 text files and use a 26-letter substitution key. It should not delay the first working version.

### Out of scope for the first release

- User accounts or multi-user access control.
- Database or cloud storage.
- Public hosting.
- Sharing links.
- Permanent server-side key storage.
- Large-file streaming or resumable uploads.
- Digital signatures, certificates, or key revocation.
- A custom implementation of RSA mathematics or AES.
- A claim that the application provides production-grade security.

## Recommended technology stack

### Frontend

- HTML for the page structure and forms.
- CSS for a small responsive interface, algorithm cards, status messages, and the disclaimer banner.
- Vanilla JavaScript for operation switching, algorithm selection, drag-and-drop, conditional fields, form submission, status updates, and downloads.

### Backend

- Python 3.
- Flask for the local server and HTTP endpoints.
- `cryptography` for RSA key generation, RSA-OAEP, AES-CBC, PKCS7 padding, HMAC, and key serialization.
- Python standard library modules such as `tempfile`, `pathlib`, `secrets`, `hashlib`, and `mimetypes` for temporary files, random values, metadata, and file handling.
- Pytest for algorithm and route tests.

The browser should not implement the cryptographic operations in the first version. It should send a local request to the Python backend, which performs validation and encryption or decryption before returning a downloadable result.

## Algorithm design

### Option 1: RSA

The RSA option is primarily for demonstrating public-key encryption, key pairs, OAEP padding, and the difference between public and private keys.

Recommended MVP design:

- Generate RSA-2048 key pairs using the cryptography library.
- Use public exponent 65537.
- Use RSA-OAEP with MGF1-SHA256 and SHA-256.
- Encrypt with the public key.
- Decrypt with the matching private key.
- Export keys as PEM files.
- Protect exported private keys with a user-provided passphrase if this can be completed within the time limit.
- Apply a strict plaintext size limit because direct RSA cannot encrypt arbitrary-sized files.

The interface should clearly state that the direct RSA option is intended for small demonstration files. The backend must reject data that is too large rather than silently truncating or attempting unsafe chunking.

If the project later needs to support larger files under an RSA-labelled workflow, the next design should be a hybrid envelope: AES encrypts the file and RSA encrypts the AES key. That is a future enhancement and should not be confused with direct RSA encryption in the first release.

The existing `Crypt_Algorithm/Crypt-Techniques/task3-rsa.py` demonstrates RSA-OAEP, signatures, RSA key generation, and PEM serialization. It should be used as reference only. The webpage should not copy its import-time execution, unencrypted private-key output, or 1024-bit demonstration path.

### Option 2: AES-CBC

The AES-CBC option is for demonstrating symmetric encryption, password-derived keys, initialization vectors, padding, and file decryption with the same password.

Recommended MVP design:

- Ask the user for a password during encryption and decryption.
- Generate a random salt for every encryption operation.
- Derive separate encryption and authentication keys with PBKDF2-HMAC-SHA256.
- Use AES-256-CBC for the file bytes.
- Generate a fresh random 16-byte IV for every encryption operation.
- Apply PKCS7 padding before encryption and remove it after decryption.
- Use Encrypt-then-MAC with HMAC-SHA256 over the format metadata, salt, IV, and ciphertext.
- Derive 64 bytes with PBKDF2-HMAC-SHA256 using 600,000 iterations, then split them into separate 32-byte encryption and authentication keys.
- Verify the HMAC before attempting to unpad or return plaintext.
- Store the salt, IV, algorithm identifier, format version, original filename, and HMAC alongside the ciphertext in an `.aescbc` package.

The package is UTF-8 JSON with Base64-encoded salt, IV, ciphertext, and HMAC.
Its authenticated manifest also records the KDF and iteration count, original
filename, and MIME type. The password is never included. The encrypted
download uses `<filename-stem>.encrypt.aescbc`; a decrypted file uses
`<original-stem>.decrypt<extension>`.

The HMAC is important because AES-CBC by itself does not authenticate the ciphertext. The design still uses AES-CBC as requested, while preventing the MVP from treating unauthenticated CBC as a complete file-protection design.

The old `task1-aes-cbc.py` and `task2-aes-cbc.py` exercises provide useful context for AES-CBC, IV handling, and PKCS7 padding. Their hard-coded password, plaintext key file, and unauthenticated CBC workflow must not be copied into the webpage.

## User process

### RSA encryption

1. The user opens the local webpage and reads the educational disclaimer.
2. The user selects **Encrypt**.
3. The user selects **RSA**.
4. The user selects a small file.
5. The user uploads an existing RSA public key or generates a new RSA key pair.
6. If a new pair is generated, the user downloads the public and private key files and keeps the private key safe for the demonstration.
7. The user submits the form.
8. The backend validates the key and RSA size limit, encrypts the file, and returns a download.

### RSA decryption

1. The user selects **Decrypt** and **RSA**.
2. The user uploads the RSA-encrypted file.
3. The user uploads the matching private key and enters its passphrase if required.
4. The backend validates the key and decrypts the file.
5. The original file is returned as a download if decryption succeeds.

### AES-CBC encryption

1. The user selects **Encrypt**.
2. The user selects **AES-CBC**.
3. The user selects a file.
4. The user chooses a passcode and confirms it.
5. The local backend generates a salt and IV, derives the keys, encrypts the file, authenticates the package, and returns an `.aescbc` download.

### AES-CBC decryption

1. The user selects **Decrypt** and **AES-CBC**.
2. The user uploads an `.aescbc` file.
3. The user enters the same passcode used during encryption.
4. The backend verifies the HMAC before decrypting and unpadding.
5. The original file is returned only if authentication and decryption succeed.

## Page and interface plan

The first release can use one page with a small amount of JavaScript state:

- Header: CipherForge name and short project description.
- Warning panel: prominent educational-only disclaimer.
- Operation control: Encrypt or Decrypt.
- Algorithm control: RSA or AES-CBC.
- File drop zone: selected filename, size, and basic type information.
- Dynamic key area:
  - RSA public/private key upload and key-generation controls.
  - AES-CBC password and confirmation fields.
- Submit button whose label changes to match the selected operation.
- Status area for validation, processing, success, and error states.
- Result area containing the download action and a reminder about required keys or passwords.

The page should not display plaintext or ciphertext unnecessarily. A visual explanation of the algorithm steps can be added later as an educational enhancement.

## API outline

These examples describe the API contract, not implementation code. All endpoints are local-only in the first version.

### `GET /api/algorithms`

Returns the currently available algorithms.

Example response shape:

```json
{
  "algorithms": [
    {
      "id": "aes-cbc",
      "label": "AES-CBC",
      "supports": ["files-within-upload-limit"],
      "educational_warning": "AES-CBC is included for educational purposes."
    },
    {
      "id": "rsa",
      "label": "RSA",
      "status": "planned",
      "supports": [],
      "educational_warning": "Direct RSA is not available yet."
    }
  ]
}
```

### `POST /api/keys/rsa`

Generates an RSA key pair for local demonstration use.

Request fields:

- `key_size`: server-controlled or restricted to approved values.
- `passphrase`: used to protect the private-key export if passphrase protection is implemented.

Response behavior:

- Provide downloadable public and private key files.
- Do not write private keys to the repository.
- Do not log key contents or passphrases.

### `POST /api/encrypt`

Multipart form fields:

- `file`: source file.
- `algorithm`: `aes-cbc` (RSA is planned for Day 2).
- `password`: required for AES-CBC.
- `password_confirmation`: required by the frontend for AES-CBC encryption.

Success behavior:

- Return the encrypted file as an attachment named `<filename-stem>.encrypt.aescbc`.
- Do not include plaintext, passwords, or private keys in the response body or logs.

### `POST /api/decrypt`

Multipart form fields:

- `file`: encrypted input file.
- `algorithm`: `aes-cbc`.
- `password`: required for AES-CBC.

Success behavior:

- Return the recovered file as an attachment named `<original-stem>.decrypt<extension>`.
- Restore the original filename only after sanitizing it and preventing path traversal.

### Error response shape

All validation and operation errors should use a consistent JSON shape, for example:

```json
{
  "error": {
    "code": "FILE_TOO_LARGE",
    "message": "The selected file exceeds the upload limit."
  }
}
```

Authentication failures, incorrect passwords, malformed packages, and wrong RSA keys should return a generic decryption error without exposing sensitive diagnostic details.

## Day 1 project structure

```text
CipherForge/
├── README.md
├── LICENSE
├── requirements.txt
├── run.py
├── app/
│   ├── __init__.py
│   ├── constants.py
│   ├── routes.py
│   ├── validators.py
│   ├── storage.py
│   └── services/
│       └── aes_cbc_service.py
├── templates/
│   └── index.html
├── static/
│   ├── css/
│   │   └── styles.css
│   └── js/
│       └── app.js
├── tests/
│   ├── test_aes_cbc_service.py
│   └── test_routes.py
└── instance/
    └── .gitkeep
```

`instance/` is ignored by Git. Upload streams are owned by Flask/Werkzeug and
closed at the end of each request. Encryption keys, plaintext, and response
packages stay in memory; the application does not create persistent temporary
files or retain passcodes.

## Validation and safety requirements

- Bind the local server to `127.0.0.1`, not all network interfaces.
- Limit source files to 20 MiB and allow request overhead for the Base64-encoded `.aescbc` package during decryption.
- Enforce a much smaller RSA-specific plaintext limit based on the configured key and OAEP hash.
- Sanitize filenames and never treat an uploaded filename as a filesystem path.
- Reject empty files if the selected operation cannot meaningfully process them.
- Validate RSA key type, serialization, key size, and passphrase before processing.
- Validate AES-CBC package version, salt, IV, ciphertext length, and HMAC before decryption.
- Use a cryptographically secure random source for RSA keys, salts, IVs, and other random values.
- Never use hard-coded passwords or keys from the reference exercises.
- Never use textbook RSA or manually implemented RSA mathematics in the webpage.
- Never return plaintext, passwords, keys, or decrypted data in logs.
- Close request-scoped upload streams after successful and failed requests; do not persist uploads, plaintext, keys, or packages.
- Show the educational disclaimer before the user selects a file.
- Explain that the local MVP is not designed for large files or sensitive information.

## Delivery sequence for a 1–3 day build

### Day 1: local skeleton and AES-CBC workflow — complete

- Create the Flask app and single-page layout.
- Add the disclaimer, operation switch, and algorithm selection.
- Add upload validation and temporary-file handling.
- Implement AES-CBC encryption, PBKDF2 key derivation, PKCS7 padding, and HMAC verification.
- Add the AES-CBC API route and service tests.

### Day 2: RSA workflow

- Add RSA key-pair generation and PEM import/export.
- Implement RSA-OAEP encryption and decryption with a strict size limit.
- Connect RSA key controls to the frontend.
- Add RSA service and route tests, including wrong-key and oversized-file cases.

### Day 3: polish and demonstration readiness

- Improve error messages, download names, and status states.
- Add responsive styling and short algorithm explanations.
- Test binary and text files through both workflows.
- Run the full test suite and manually verify the browser process.
- Document local setup and a short demonstration script.
- Prepare screenshots or a short local demo recording for future portfolio use.

If time is limited, visual polish and passphrase-protected RSA private-key export can be secondary tasks. The core success criterion is a reliable local encrypt/decrypt round trip for RSA and AES-CBC, with the educational warning always visible.

## Testing checklist

### RSA

- Generate a key pair and successfully import the resulting files.
- Encrypt and decrypt a small text file.
- Encrypt and decrypt a small binary file.
- Confirm that decrypted bytes exactly match the original bytes.
- Reject data above the direct RSA size limit.
- Reject a wrong private key.
- Reject malformed RSA-encrypted input.
- Confirm that private keys, plaintext, and passphrases are absent from logs.

### AES-CBC

- Encrypt and decrypt a text file with the same password.
- Encrypt and decrypt a binary file within the upload limit.
- Confirm that decrypted bytes exactly match the original bytes.
- Confirm that different encryptions use different salts and IVs.
- Reject an incorrect password.
- Reject modified ciphertext or metadata through HMAC verification.
- Reject invalid padding and malformed package structures.
- Confirm that passwords and plaintext are absent from logs.

### Web interface

- Confirm that changing the algorithm changes the visible key fields.
- Confirm that changing Encrypt to Decrypt changes the required inputs.
- Confirm that invalid forms do not trigger unnecessary processing.
- Confirm that successful responses download with the expected extension.
- Confirm that temporary files are removed after success and failure.
- Confirm that the server is reachable only through the intended local address.
- Confirm that the educational disclaimer is visible before file selection.

## Future substitution-cipher phase

After RSA and AES-CBC are complete, the substitution cipher can be added as a third selectable option.

The later feature should:

- Accept UTF-8 text files only.
- Require or generate a 26-letter substitution key.
- Preserve case, punctuation, whitespace, and line breaks where possible.
- Reject keys that are not exactly 26 unique alphabetic characters.
- Keep the key separate from the output file.
- State clearly that substitution is easily broken and is included only for education.

## Future hosting direction

Hosting should be treated as a separate project phase. Before exposing CipherForge publicly, the project would need HTTPS, an explicit storage and deletion policy, stronger upload controls, rate limiting, dependency maintenance, secure secret handling, monitoring, and a decision about whether server-side plaintext processing is acceptable.

For a resume or LinkedIn demonstration, a local demo video, screenshots, and a repository link are appropriate. A public deployment should not imply secure file storage unless those operational controls have actually been implemented.

## Reference documentation

- [Python `cryptography` RSA documentation](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/)
- [Python `cryptography` symmetric-encryption documentation](https://cryptography.io/en/stable/hazmat/primitives/symmetric-encryption/)
- [Python `cryptography` PBKDF2 documentation](https://cryptography.io/en/stable/hazmat/primitives/key-derivation-functions/)
- [Flask file-upload documentation](https://flask.palletsprojects.com/en/stable/patterns/fileuploads/)
