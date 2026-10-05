"use strict";

// Opened directly, this page is a preview. Through Flask, requests go only to
// the local CipherForge API.
(() => {
  const MAX_SOURCE_FILE_BYTES = 20 * 1024 * 1024;
  const MAX_PACKAGE_FILE_BYTES = Math.ceil((MAX_SOURCE_FILE_BYTES + 16) / 3) * 4 + 64 * 1024;
  const MAX_RSA_PLAINTEXT_BYTES = 190;
  const MAX_RSA_ENCRYPTED_FILE_BYTES = 64 * 1024;

  const form = document.querySelector("#crypto-form");
  const operationButtons = [...document.querySelectorAll("[data-operation]")];
  const algorithmInputs = [...document.querySelectorAll('input[name="algorithm"]')];
  const fileInput = document.querySelector("#file-input");
  const dropZone = document.querySelector("#drop-zone");
  const fileHint = document.querySelector("#file-hint");
  const fileLimitLabel = document.querySelector("#file-limit-label");
  const algorithmFootnote = document.querySelector("#algorithm-footnote");
  const selectedFile = document.querySelector("#selected-file");
  const fileName = document.querySelector("#file-name");
  const fileSize = document.querySelector("#file-size");
  const removeFileButton = document.querySelector("#remove-file");
  const aesPasswordFields = document.querySelector("#aes-password-fields");
  const passwordInput = document.querySelector("#password-input");
  const passwordLabel = document.querySelector("#password-label");
  const passwordHelp = document.querySelector("#password-help");
  const confirmGroup = document.querySelector("#confirm-group");
  const confirmInput = document.querySelector("#confirm-input");
  const rsaKeyFields = document.querySelector("#rsa-key-fields");
  const rsaModes = [...document.querySelectorAll("[data-rsa-mode]")];
  const rsaPublicKeyInput = document.querySelector("#rsa-public-key-input");
  const rsaPrivateKeyInput = document.querySelector("#rsa-private-key-input");
  const rsaPassphraseInput = document.querySelector("#rsa-passphrase-input");
  const rsaGenerationPassphrase = document.querySelector("#rsa-generation-passphrase");
  const rsaGenerationConfirmation = document.querySelector("#rsa-generation-confirmation");
  const generateRsaKeysButton = document.querySelector("#generate-rsa-keys");
  const submitLabel = document.querySelector("#submit-label");
  const statusMessage = document.querySelector("#form-status");
  const downloadLink = document.querySelector("#download-result");
  const downloadFilename = document.querySelector("#download-filename");
  const currentStep = document.querySelector("#current-step");

  if (!form || !fileInput) return;

  let currentOperation = "encrypt";
  let currentAlgorithm = "aes-cbc";
  let currentDownloadUrl = null;
  let operationComplete = false;
  const processSteps = [1, 2, 3].map((step) => document.querySelector(`[data-process-step="${step}"]`));

  function currentFileLimit() {
    if (currentAlgorithm === "rsa") {
      return currentOperation === "encrypt" ? MAX_RSA_PLAINTEXT_BYTES : MAX_RSA_ENCRYPTED_FILE_BYTES;
    }
    return currentOperation === "encrypt" ? MAX_SOURCE_FILE_BYTES : MAX_PACKAGE_FILE_BYTES;
  }

  function expectedExtension() {
    if (currentOperation !== "decrypt") return "";
    return currentAlgorithm === "rsa" ? ".rsaenc" : ".aescbc";
  }

  function clearDownload() {
    if (currentDownloadUrl) URL.revokeObjectURL(currentDownloadUrl);
    currentDownloadUrl = null;
    downloadLink.hidden = true;
    downloadLink.removeAttribute("href");
    downloadLink.removeAttribute("download");
    downloadFilename.textContent = "Your file is ready";
  }

  function updateStatus(message, state = "info") {
    statusMessage.textContent = message;
    statusMessage.hidden = false;
    statusMessage.classList.toggle("is-error", state === "error");
  }

  function clearStatus() {
    statusMessage.textContent = "";
    statusMessage.hidden = true;
    statusMessage.classList.remove("is-error");
  }

  function formatFileSize(bytes) {
    if (bytes < 1024) return `${bytes} bytes`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  }

  function formatLimit(bytes) {
    if (bytes < 1024) return `${bytes} bytes`;
    if (bytes < 1024 * 1024) return `${Math.ceil(bytes / 1024)} KB`;
    return `${Math.ceil(bytes / (1024 * 1024))} MB`;
  }

  function selectedKeyReady() {
    if (currentAlgorithm !== "rsa") return Boolean(passwordInput.value.trim());
    const keyInput = currentOperation === "encrypt" ? rsaPublicKeyInput : rsaPrivateKeyInput;
    return Boolean(keyInput.files && keyInput.files[0]);
  }

  function updateProcessSteps() {
    const selected = fileInput.files && fileInput.files[0];
    const extension = expectedExtension();
    const fileChosen = Boolean(
      selected && selected.size <= currentFileLimit() && (!extension || selected.name.toLowerCase().endsWith(extension)),
    );
    const keyReady = selectedKeyReady();
    const confirmationReady =
      currentAlgorithm === "rsa" || currentOperation === "decrypt" || confirmInput.value === passwordInput.value;
    const stepTwoReady = fileChosen && keyReady && confirmationReady;
    processSteps[0].classList.add("is-active");
    const [_, stepTwo, stepThree] = processSteps;
    stepTwo.classList.toggle("is-active", fileChosen || keyReady || operationComplete);
    stepTwo.classList.toggle("is-complete", stepTwoReady || operationComplete);
    stepThree.classList.toggle("is-active", stepTwoReady && !operationComplete);
    stepThree.classList.toggle("is-complete", operationComplete);
    currentStep.textContent = operationComplete || stepTwoReady ? "03" : fileChosen || keyReady ? "02" : "01";
  }

  function setFile(file) {
    operationComplete = false;
    clearStatus();
    clearDownload();

    if (!file) return;
    if (file.size === 0) {
      fileInput.value = "";
      selectedFile.hidden = true;
      fileName.textContent = "";
      fileSize.textContent = "";
      updateProcessSteps();
      updateStatus("Choose a file that contains data. Empty files can’t be processed.", "error");
      return;
    }
    if (file.size > currentFileLimit()) {
      fileInput.value = "";
      selectedFile.hidden = true;
      fileName.textContent = "";
      fileSize.textContent = "";
      updateProcessSteps();
      updateStatus(
        `That file exceeds the ${formatLimit(currentFileLimit())} limit for this workflow. Choose a smaller file.`,
        "error",
      );
      return;
    }

    fileName.textContent = file.name;
    fileSize.textContent = formatFileSize(file.size);
    selectedFile.hidden = false;
    fileInput.setCustomValidity("");
    const extension = expectedExtension();
    if (extension && !file.name.toLowerCase().endsWith(extension)) {
      updateStatus(`Choose a ${extension} encrypted package to decrypt.`, "error");
    }
    updateProcessSteps();
  }

  function clearFile() {
    operationComplete = false;
    fileInput.value = "";
    fileInput.setCustomValidity("");
    selectedFile.hidden = true;
    fileName.textContent = "";
    fileSize.textContent = "";
    clearStatus();
    clearDownload();
    updateProcessSteps();
    fileInput.focus();
  }

  function updateDynamicFields() {
    const isEncrypt = currentOperation === "encrypt";
    const isRsa = currentAlgorithm === "rsa";
    aesPasswordFields.hidden = isRsa;
    rsaKeyFields.hidden = !isRsa;
    rsaModes.forEach((mode) => {
      mode.hidden = !isRsa || mode.dataset.rsaMode !== currentOperation;
    });
    rsaPublicKeyInput.required = isRsa && isEncrypt;
    rsaPrivateKeyInput.required = isRsa && !isEncrypt;
    rsaPublicKeyInput.disabled = !isRsa || !isEncrypt;
    rsaPrivateKeyInput.disabled = !isRsa || isEncrypt;
    rsaPassphraseInput.disabled = !isRsa || isEncrypt;
    passwordInput.required = !isRsa;
    confirmInput.required = !isRsa && isEncrypt;

    passwordLabel.textContent = isEncrypt ? "Create a passcode" : "Enter your passcode";
    passwordInput.autocomplete = isEncrypt ? "new-password" : "current-password";
    passwordInput.placeholder = isEncrypt
      ? "Enter a passcode for this file"
      : "Enter the passcode used to encrypt this file";
    passwordHelp.textContent = isEncrypt
      ? "You’ll need this same passcode to decrypt the file later."
      : "Enter the passcode that was used to encrypt this file.";
    confirmGroup.hidden = !isEncrypt;
    submitLabel.textContent = `${isEncrypt ? "Encrypt" : "Decrypt"} file`;

    if (isRsa) {
      fileInput.accept = isEncrypt ? "" : ".rsaenc";
      fileHint.textContent = isEncrypt
        ? "RSA-2048 direct encryption · Max 190 bytes · Processed by your local app"
        : ".rsaenc packages · Max 64 KB · Processed by your local app";
      fileLimitLabel.textContent = isEncrypt ? "MAX 190 BYTES" : "MAX 64 KB";
      algorithmFootnote.innerHTML = "<span aria-hidden=\"true\">✳</span> Direct RSA is for tiny demonstration files; images usually exceed 190 bytes.";
    } else {
      fileInput.accept = isEncrypt ? "" : ".aescbc";
      fileHint.textContent = isEncrypt
        ? "Any file type · Max 20 MB · Processed by your local app"
        : ".aescbc packages · Max 27 MB · Processed by your local app";
      fileLimitLabel.textContent = isEncrypt ? "UP TO 20 MB" : "MAX 27 MB";
      algorithmFootnote.innerHTML = "<span aria-hidden=\"true\">✳</span> AES-CBC accepts files up to 20 MB.";
    }
  }

  function setOperation(operation) {
    operationComplete = false;
    currentOperation = operation;
    operationButtons.forEach((button) => {
      const isSelected = button.dataset.operation === operation;
      button.classList.toggle("is-selected", isSelected);
      button.setAttribute("aria-pressed", String(isSelected));
    });

    passwordInput.value = "";
    confirmInput.value = "";
    passwordInput.type = "password";
    confirmInput.type = "password";
    document.querySelectorAll("[data-reveal]").forEach((button) => {
      button.setAttribute("aria-label", button.dataset.reveal === "password-input" ? "Show password" : "Show confirmation password");
    });
    updateDynamicFields();
    clearStatus();
    clearDownload();
    setFile(fileInput.files && fileInput.files[0]);
    updateProcessSteps();
  }

  function setAlgorithm(algorithm) {
    operationComplete = false;
    currentAlgorithm = algorithm;
    algorithmInputs.forEach((input) => input.closest(".algorithm-card").classList.toggle("is-selected", input.value === algorithm));
    passwordInput.value = "";
    confirmInput.value = "";
    rsaPassphraseInput.value = "";
    updateDynamicFields();
    clearStatus();
    clearDownload();
    setFile(fileInput.files && fileInput.files[0]);
    updateProcessSteps();
  }

  function validateForm() {
    const file = fileInput.files && fileInput.files[0];
    const extension = expectedExtension();
    confirmInput.setCustomValidity("");

    if (!file) {
      updateStatus("Choose a file before continuing.", "error");
      return false;
    }
    if (file.size === 0 || file.size > currentFileLimit()) {
      updateStatus(`Choose a non-empty file within the ${formatLimit(currentFileLimit())} limit.`, "error");
      return false;
    }
    if (extension && !file.name.toLowerCase().endsWith(extension)) {
      updateStatus(`Choose a ${extension} encrypted package to decrypt.`, "error");
      return false;
    }

    if (currentAlgorithm === "rsa") {
      const keyInput = currentOperation === "encrypt" ? rsaPublicKeyInput : rsaPrivateKeyInput;
      const keyDescription = currentOperation === "encrypt" ? "public" : "private";
      if (!keyInput.files || !keyInput.files[0]) {
        keyInput.focus();
        updateStatus(`Choose the RSA ${keyDescription} key to continue.`, "error");
        return false;
      }
      return true;
    }

    if (!passwordInput.value) {
      passwordInput.focus();
      passwordInput.reportValidity();
      updateStatus("Enter the AES-CBC password to continue.", "error");
      return false;
    }
    if (currentOperation === "encrypt" && passwordInput.value !== confirmInput.value) {
      confirmInput.setCustomValidity("The passwords don’t match.");
      confirmInput.reportValidity();
      updateStatus("The passcode entries don’t match. Check them and try again.", "error");
      return false;
    }
    return true;
  }

  async function generateRsaKeyPair() {
    clearStatus();
    if (window.location.protocol === "file:") {
      updateStatus("Start CipherForge with `python run.py` before generating keys.", "error");
      return;
    }
    const passphrase = rsaGenerationPassphrase.value;
    if (passphrase && passphrase !== rsaGenerationConfirmation.value) {
      updateStatus("The optional private-key passphrase entries do not match.", "error");
      return;
    }
    if (!passphrase && rsaGenerationConfirmation.value) {
      updateStatus("Enter the private-key passphrase in both fields or leave both blank.", "error");
      return;
    }

    const keyRequest = new FormData();
    keyRequest.set("key_size", "2048");
    keyRequest.set("passphrase", passphrase);
    keyRequest.set("passphrase_confirmation", rsaGenerationConfirmation.value);
    generateRsaKeysButton.disabled = true;
    updateStatus("Generating your RSA-2048 key pair…");
    try {
      const response = await fetch("/api/keys/rsa", {
        method: "POST",
        body: keyRequest,
        headers: { Accept: "application/zip, application/json" },
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw new Error(payload?.error?.message || "The key-pair request could not be completed.");
      }
      const keyArchive = await response.blob();
      if (!keyArchive.size) throw new Error("The server returned an empty key archive.");
      const archiveUrl = URL.createObjectURL(keyArchive);
      const anchor = document.createElement("a");
      anchor.href = archiveUrl;
      anchor.download = response.headers.get("X-Download-Filename") || "cipherforge-rsa-2048-key-pair.zip";
      document.body.append(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(archiveUrl), 1000);
      rsaGenerationPassphrase.value = "";
      rsaGenerationConfirmation.value = "";
      updateStatus("Your key-pair ZIP is ready. Extract it, keep the private PEM safe, then choose the public PEM above.");
    } catch (error) {
      updateStatus(
        error instanceof TypeError
          ? "Could not reach CipherForge. Start it with `python run.py` and open http://127.0.0.1:5000."
          : error.message,
        "error",
      );
    } finally {
      generateRsaKeysButton.disabled = false;
    }
  }

  operationButtons.forEach((button) => {
    button.addEventListener("click", () => setOperation(button.dataset.operation));
  });
  algorithmInputs.forEach((input) => {
    input.addEventListener("change", () => setAlgorithm(input.value));
  });
  fileInput.addEventListener("change", () => setFile(fileInput.files && fileInput.files[0]));
  removeFileButton.addEventListener("click", clearFile);
  [passwordInput, confirmInput, rsaPublicKeyInput, rsaPrivateKeyInput, rsaPassphraseInput].forEach((input) => {
    ["input", "change"].forEach((eventName) => {
      input.addEventListener(eventName, () => {
        operationComplete = false;
        if (input === passwordInput || input === confirmInput) confirmInput.setCustomValidity("");
        clearStatus();
        updateProcessSteps();
      });
    });
  });
  generateRsaKeysButton.addEventListener("click", generateRsaKeyPair);

  document.querySelectorAll("[data-reveal]").forEach((button) => {
    button.addEventListener("click", () => {
      const target = document.getElementById(button.dataset.reveal);
      if (!target) return;
      const reveal = target.type === "password";
      target.type = reveal ? "text" : "password";
      button.setAttribute("aria-label", reveal ? "Hide password" : "Show password");
    });
  });
  ["dragenter", "dragover"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropZone.classList.add("is-dragging");
    });
  });
  ["dragleave", "drop"].forEach((eventName) => {
    dropZone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropZone.classList.remove("is-dragging");
    });
  });
  dropZone.addEventListener("drop", (event) => {
    const file = event.dataTransfer && event.dataTransfer.files[0];
    if (!file) return;
    try {
      const transfer = new DataTransfer();
      transfer.items.add(file);
      fileInput.files = transfer.files;
      setFile(file);
    } catch {
      updateStatus("This browser can’t attach a dropped file here. Use browse to select it.", "error");
    }
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    clearStatus();
    clearDownload();
    if (!validateForm()) return;
    if (window.location.protocol === "file:") {
      updateStatus(
        "To process a file, start CipherForge with `python run.py` and open http://127.0.0.1:5000. This static preview does not send your file anywhere.",
        "error",
      );
      return;
    }

    const operation = currentOperation;
    const algorithm = currentAlgorithm;
    const formData = new FormData(form);
    form.querySelectorAll("button, input").forEach((control) => {
      control.disabled = true;
    });
    updateStatus(operation === "encrypt" ? "Encrypting your file…" : "Decrypting your file…");
    try {
      const response = await fetch(operation === "encrypt" ? "/api/encrypt" : "/api/decrypt", {
        method: "POST",
        body: formData,
        headers: { Accept: "application/octet-stream, application/json" },
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw new Error(payload?.error?.message || "The request could not be completed.");
      }
      const output = await response.blob();
      if (!output.size) throw new Error("The server returned an empty file.");

      currentDownloadUrl = URL.createObjectURL(output);
      downloadLink.href = currentDownloadUrl;
      downloadLink.download = response.headers.get("X-Download-Filename") || "processed-file";
      downloadFilename.textContent = downloadLink.download;
      downloadLink.hidden = false;
      passwordInput.value = "";
      confirmInput.value = "";
      rsaPassphraseInput.value = "";
      operationComplete = true;
      updateProcessSteps();
      updateStatus(
        operation === "encrypt"
          ? algorithm === "rsa"
            ? "RSA encryption is complete. Keep the matching private key and its passphrase safe."
            : "Encryption is complete. Keep your passcode somewhere safe; it is not stored in the package."
          : "Decryption is complete. Download the recovered file below.",
      );
    } catch (error) {
      updateStatus(
        error instanceof TypeError
          ? "Could not reach CipherForge. Start it with `python run.py` and open http://127.0.0.1:5000."
          : error.message,
        "error",
      );
    } finally {
      form.querySelectorAll("button, input").forEach((control) => {
        control.disabled = false;
      });
      updateDynamicFields();
    }
  });

  updateDynamicFields();
  updateProcessSteps();
})();
