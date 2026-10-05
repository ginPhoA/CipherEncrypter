"use strict";

// Opening this HTML file directly gives a local-only preview. When served by
// Flask, form submissions go only to the local CipherForge API.
(() => {
  const MAX_SOURCE_FILE_BYTES = 20 * 1024 * 1024;
  const MAX_PACKAGE_FILE_BYTES =
    Math.ceil((MAX_SOURCE_FILE_BYTES + 16) / 3) * 4 + 64 * 1024;

  const form = document.querySelector("#crypto-form");
  const operationButtons = [...document.querySelectorAll("[data-operation]")];
  const fileInput = document.querySelector("#file-input");
  const dropZone = document.querySelector("#drop-zone");
  const fileHint = document.querySelector("#file-hint");
  const selectedFile = document.querySelector("#selected-file");
  const fileName = document.querySelector("#file-name");
  const fileSize = document.querySelector("#file-size");
  const removeFileButton = document.querySelector("#remove-file");
  const passwordInput = document.querySelector("#password-input");
  const passwordLabel = document.querySelector("#password-label");
  const passwordHelp = document.querySelector("#password-help");
  const confirmGroup = document.querySelector("#confirm-group");
  const confirmInput = document.querySelector("#confirm-input");
  const submitLabel = document.querySelector("#submit-label");
  const statusMessage = document.querySelector("#form-status");
  const downloadLink = document.querySelector("#download-result");
  const downloadFilename = document.querySelector("#download-filename");
  const submitButton = document.querySelector("#submit-button");
  const currentStep = document.querySelector("#current-step");

  if (!form || !fileInput) return;

  let currentOperation = "encrypt";
  let currentDownloadUrl = null;
  let operationComplete = false;

  function currentFileLimit() {
    return currentOperation === "encrypt" ? MAX_SOURCE_FILE_BYTES : MAX_PACKAGE_FILE_BYTES;
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
      const limitMb = Math.ceil(currentFileLimit() / (1024 * 1024));
      updateStatus(`That file exceeds the ${limitMb} MB preview limit. Choose a smaller file.`, "error");
      return;
    }

    fileName.textContent = file.name;
    fileSize.textContent = formatFileSize(file.size);
    selectedFile.hidden = false;
    fileInput.setCustomValidity("");
    if (currentOperation === "decrypt" && !file.name.toLowerCase().endsWith(".aescbc")) {
      updateStatus("AES-CBC decryption expects a .aescbc package.", "error");
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

  function updateProcessSteps() {
    const selected = fileInput.files && fileInput.files[0];
    const fileChosen = Boolean(
      selected &&
        selected.size <= currentFileLimit() &&
        (currentOperation === "encrypt" || selected.name.toLowerCase().endsWith(".aescbc")),
    );
    const passwordReady = Boolean(passwordInput.value.trim());
    const confirmationReady = currentOperation === "decrypt" || confirmInput.value === passwordInput.value;
    const stepTwoReady = fileChosen && passwordReady && confirmationReady;
    const stepTwo = document.querySelector('[data-process-step="2"]');
    const stepThree = document.querySelector('[data-process-step="3"]');

    document.querySelector('[data-process-step="1"]').classList.add("is-active");
    stepTwo.classList.toggle("is-active", fileChosen || passwordReady || operationComplete);
    stepTwo.classList.toggle("is-complete", stepTwoReady || operationComplete);
    stepThree.classList.toggle("is-active", stepTwoReady && !operationComplete);
    stepThree.classList.toggle("is-complete", operationComplete);
    currentStep.textContent = operationComplete || stepTwoReady ? "03" : fileChosen || passwordReady ? "02" : "01";
  }

  function setOperation(operation) {
    operationComplete = false;
    currentOperation = operation;
    const isEncrypt = operation === "encrypt";

    operationButtons.forEach((button) => {
      const isSelected = button.dataset.operation === operation;
      button.classList.toggle("is-selected", isSelected);
      button.setAttribute("aria-pressed", String(isSelected));
    });

    passwordLabel.textContent = isEncrypt ? "Create a passcode" : "Enter your passcode";
    passwordInput.autocomplete = isEncrypt ? "new-password" : "current-password";
    passwordInput.placeholder = isEncrypt
      ? "Enter a passcode for this file"
      : "Enter the passcode used to encrypt this file";
    passwordHelp.textContent = isEncrypt
      ? "You’ll need this same passcode to decrypt the file later."
      : "Enter the passcode that was used to encrypt this file.";
    confirmGroup.hidden = !isEncrypt;
    confirmInput.required = isEncrypt;
    submitLabel.textContent = isEncrypt ? "Encrypt file" : "Decrypt file";
    fileInput.accept = isEncrypt ? "" : ".aescbc";
    fileHint.textContent = isEncrypt
      ? "Any file type · Max 20 MB · Processed by your local app"
      : ".aescbc packages · Max 27 MB · Processed by your local app";
    passwordInput.value = "";
    confirmInput.value = "";
    passwordInput.type = "password";
    confirmInput.type = "password";
    document.querySelectorAll("[data-reveal]").forEach((button) => {
      button.setAttribute("aria-label", button.dataset.reveal === "password-input" ? "Show password" : "Show confirmation password");
    });
    clearStatus();
    clearDownload();
    updateProcessSteps();
  }

  function validateForm() {
    const file = fileInput.files && fileInput.files[0];
    confirmInput.setCustomValidity("");

    if (!file) {
      updateStatus("Choose a file before continuing.", "error");
      return false;
    }
    if (file.size === 0 || file.size > currentFileLimit()) {
      const limitMb = Math.ceil(currentFileLimit() / (1024 * 1024));
      updateStatus(`Choose a non-empty file within the ${limitMb} MB upload limit.`, "error");
      return false;
    }
    if (currentOperation === "decrypt" && !file.name.toLowerCase().endsWith(".aescbc")) {
      updateStatus("Choose an AES-CBC .aescbc package to decrypt.", "error");
      return false;
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

  operationButtons.forEach((button) => {
    button.addEventListener("click", () => setOperation(button.dataset.operation));
  });

  fileInput.addEventListener("change", () => {
    setFile(fileInput.files && fileInput.files[0]);
  });

  removeFileButton.addEventListener("click", clearFile);

  [passwordInput, confirmInput].forEach((input) => {
    input.addEventListener("input", () => {
      operationComplete = false;
      confirmInput.setCustomValidity("");
      clearStatus();
      updateProcessSteps();
    });
  });

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
    const formData = new FormData(form);
    formData.set("algorithm", "aes-cbc");
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
        const message = payload?.error?.message || "The request could not be completed.";
        throw new Error(message);
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
      operationComplete = true;
      updateProcessSteps();
      updateStatus(
        operation === "encrypt"
          ? "Encryption is complete. Keep your passcode somewhere safe; it is not stored in the package."
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
    }
  });

  updateProcessSteps();
})();
