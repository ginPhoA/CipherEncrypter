"use strict";

// Browser implementation of the file formats in app/services/.
(() => {
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const MAX_SOURCE_BYTES = 20 * 1024 * 1024;
  const MAX_PACKAGE_BYTES = Math.ceil((MAX_SOURCE_BYTES + 16) / 3) * 4 + 64 * 1024;
  const MAX_RSA_PACKAGE_BYTES = 64 * 1024;
  const MAX_PASSWORD_BYTES = 1024;
  const PBKDF2_ITERATIONS = 600_000;

  function randomBytes(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    return bytes;
  }

  function base64(bytes) {
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
    }
    return btoa(binary);
  }

  function fromBase64(value) {
    if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
      throw new Error("The encrypted file is invalid.");
    }
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  function concatBytes(...parts) {
    const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
    let offset = 0;
    for (const part of parts) {
      result.set(part, offset);
      offset += part.length;
    }
    return result;
  }

  function canonicalJson(value) {
    if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
    if (value && typeof value === "object") {
      return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
    }
    return JSON.stringify(value);
  }

  function mimeTypeFor(fileName, selectedType = "") {
    if (/^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/.test(selectedType)) return selectedType;
    const extension = fileName.split(".").pop().toLowerCase();
    const known = {
      txt: "text/plain", html: "text/html", css: "text/css", js: "text/javascript",
      json: "application/json", pdf: "application/pdf", png: "image/png", jpg: "image/jpeg",
      jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp", svg: "image/svg+xml",
      zip: "application/zip", csv: "text/csv", xml: "application/xml", mp3: "audio/mpeg",
      mp4: "video/mp4", doc: "application/msword", docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    };
    return known[extension] || null;
  }

  function fileStem(name) {
    const dot = name.lastIndexOf(".");
    return dot > 0 ? name.slice(0, dot) : name;
  }

  function downloadedName(name, marker) {
    const dot = name.lastIndexOf(".");
    const stem = dot > 0 ? name.slice(0, dot) : name;
    const extension = dot > 0 ? name.slice(dot) : "";
    return `${stem}.${marker}${extension}`;
  }

  function safeFilename(name) {
    const safe = name.split(/[\\/]/).pop().normalize("NFKD").replace(/[\u0300-\u036f]/g, "")
      .replace(/[^A-Za-z0-9_.-]+/g, "_").replace(/^\.+/, "").replace(/[. ]+$/, "");
    return safe.slice(0, 255) || "recovered-file";
  }

  async function deriveAesKeys(password, salt) {
    const passwordBytes = encoder.encode(password);
    if (!password.trim() || passwordBytes.length > MAX_PASSWORD_BYTES) {
      throw new Error("Enter a passcode of 1,024 UTF-8 bytes or fewer.");
    }
    const material = await crypto.subtle.importKey("raw", passwordBytes, "PBKDF2", false, ["deriveBits"]);
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
      material,
      512,
    ));
    return [bits.slice(0, 32), bits.slice(32)];
  }

  async function hmac(keyBytes, data) {
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  }

  function equalBytes(left, right) {
    if (left.length !== right.length) return false;
    let difference = 0;
    for (let index = 0; index < left.length; index += 1) difference |= left[index] ^ right[index];
    return difference === 0;
  }

  async function encryptAes(file, password) {
    if (!file.size || file.size > MAX_SOURCE_BYTES) throw new Error("Choose a non-empty file no larger than 20 MiB.");
    if (Array.from(file.name).length > 255) throw new Error("The filename is too long.");
    const salt = randomBytes(16);
    const iv = randomBytes(16);
    const [encryptionBytes, macBytes] = await deriveAesKeys(password, salt);
    const encryptionKey = await crypto.subtle.importKey("raw", encryptionBytes, "AES-CBC", false, ["encrypt"]);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, encryptionKey, await file.arrayBuffer()));
    const manifest = {
      format_version: 1,
      algorithm: "AES-256-CBC-HMAC-SHA256",
      kdf: "PBKDF2-HMAC-SHA256",
      iterations: PBKDF2_ITERATIONS,
      original_filename: file.name,
      mime_type: mimeTypeFor(file.name, file.type),
      salt: base64(salt),
      iv: base64(iv),
      ciphertext: base64(ciphertext),
    };
    manifest.hmac = base64(await hmac(macBytes, encoder.encode(canonicalJson(manifest))));
    return {
      blob: new Blob([encoder.encode(canonicalJson(manifest))], { type: "application/octet-stream" }),
      name: `${fileStem(file.name)}.encrypt.aescbc`,
    };
  }

  async function decryptAes(file, password) {
    if (!file.size || file.size > MAX_PACKAGE_BYTES) throw new Error("Choose a non-empty .aescbc package within the 27 MiB limit.");
    let manifest;
    try {
      manifest = JSON.parse(decoder.decode(await file.arrayBuffer()));
    } catch {
      throw new Error("Could not decrypt this file. Check the passcode and encrypted package.");
    }
    const fields = ["algorithm", "ciphertext", "format_version", "hmac", "iterations", "iv", "kdf", "mime_type", "original_filename", "salt"];
    if (!manifest || typeof manifest !== "object" || Array.isArray(manifest) || Object.keys(manifest).sort().join("\0") !== fields.join("\0") ||
        manifest.format_version !== 1 || manifest.algorithm !== "AES-256-CBC-HMAC-SHA256" ||
        manifest.kdf !== "PBKDF2-HMAC-SHA256" || manifest.iterations !== PBKDF2_ITERATIONS ||
        typeof manifest.original_filename !== "string" || !manifest.original_filename || Array.from(manifest.original_filename).length > 255 ||
        !(manifest.mime_type === null || (typeof manifest.mime_type === "string" && /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/.test(manifest.mime_type)))) {
      throw new Error("Could not decrypt this file. Check the passcode and encrypted package.");
    }
    try {
      const salt = fromBase64(manifest.salt);
      const iv = fromBase64(manifest.iv);
      const ciphertext = fromBase64(manifest.ciphertext);
      const tag = fromBase64(manifest.hmac);
      if (salt.length !== 16 || iv.length !== 16 || tag.length !== 32 || !ciphertext.length || ciphertext.length % 16 || ciphertext.length > MAX_SOURCE_BYTES + 16) throw new Error();
      const [encryptionBytes, macBytes] = await deriveAesKeys(password, salt);
      const unsigned = { ...manifest };
      delete unsigned.hmac;
      if (!equalBytes(tag, await hmac(macBytes, encoder.encode(canonicalJson(unsigned))))) throw new Error();
      const key = await crypto.subtle.importKey("raw", encryptionBytes, "AES-CBC", false, ["decrypt"]);
      const plaintext = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, ciphertext);
      const recoveredName = safeFilename(manifest.original_filename);
      return {
        blob: new Blob([plaintext], { type: manifest.mime_type || "application/octet-stream" }),
        name: downloadedName(recoveredName, "decrypt"),
      };
    } catch {
      throw new Error("Could not decrypt this file. The passcode may not match, or the package may be invalid.");
    }
  }

  function pemBytes(pem, label) {
    const begin = `-----BEGIN ${label}-----`;
    const end = `-----END ${label}-----`;
    const text = pem.trim();
    if (!text.startsWith(begin) || !text.endsWith(end)) throw new Error(`Choose a valid ${label.toLowerCase()} PEM file.`);
    return fromBase64(text.slice(begin.length, -end.length).replace(/\s/g, ""));
  }

  function toPem(label, bytes) {
    const encoded = base64(bytes).match(/.{1,64}/g).join("\n");
    return `-----BEGIN ${label}-----\n${encoded}\n-----END ${label}-----\n`;
  }

  function readDer(data, offset = 0) {
    if (offset + 2 > data.length) throw new Error("Invalid key format.");
    const tag = data[offset];
    let length = data[offset + 1];
    let head = 2;
    if (length & 0x80) {
      const count = length & 0x7f;
      if (!count || count > 4 || offset + 2 + count > data.length) throw new Error("Invalid key format.");
      length = 0;
      for (let index = 0; index < count; index += 1) length = length * 256 + data[offset + 2 + index];
      head += count;
    }
    const start = offset + head;
    const end = start + length;
    if (end > data.length) throw new Error("Invalid key format.");
    return { tag, start, end, next: end };
  }

  function derChildren(data, node) {
    const children = [];
    let offset = node.start;
    while (offset < node.end) {
      const child = readDer(data, offset);
      children.push(child);
      offset = child.next;
    }
    if (offset !== node.end) throw new Error("Invalid key format.");
    return children;
  }

  function derContent(data, node, tag) {
    if (node.tag !== tag) throw new Error("Invalid key format.");
    return data.slice(node.start, node.end);
  }

  function decodeOid(bytes) {
    if (!bytes.length) throw new Error("Invalid key format.");
    const values = [];
    let value = 0;
    for (let index = 0; index < bytes.length; index += 1) {
      value = value * 128 + (bytes[index] & 0x7f);
      if (!(bytes[index] & 0x80)) {
        values.push(value);
        value = 0;
      }
    }
    if (value || !values.length) throw new Error("Invalid key format.");
    const first = values.shift();
    const firstArc = first < 40 ? 0 : first < 80 ? 1 : 2;
    const arcs = [firstArc, first - firstArc * 40, ...values];
    return arcs.join(".");
  }

  function derIntegerValue(data, node) {
    const bytes = derContent(data, node, 0x02);
    if (!bytes.length || bytes.length > 5) throw new Error("Invalid key parameters.");
    return bytes.reduce((value, byte) => value * 256 + byte, 0);
  }

  async function decryptEncryptedPkcs8(der, passphrase) {
    if (!passphrase || encoder.encode(passphrase).length > MAX_PASSWORD_BYTES) throw new Error("Enter the passphrase for this encrypted private key.");
    const root = readDer(der);
    const rootChildren = derChildren(der, root);
    if (root.tag !== 0x30 || rootChildren.length !== 2) throw new Error("Invalid encrypted private key.");
    const algorithmParts = derChildren(der, rootChildren[0]);
    if (decodeOid(derContent(der, algorithmParts[0], 0x06)) !== "1.2.840.113549.1.5.13") throw new Error("This encrypted key format is not supported.");
    const pbes2 = derChildren(der, algorithmParts[1]);
    const kdf = derChildren(der, pbes2[0]);
    if (decodeOid(derContent(der, kdf[0], 0x06)) !== "1.2.840.113549.1.5.12") throw new Error("This encrypted key format is not supported.");
    const kdfParameters = derChildren(der, kdf[1]);
    const salt = derContent(der, kdfParameters[0], 0x04);
    const iterations = derIntegerValue(der, kdfParameters[1]);
    if (!salt.length || iterations < 1 || iterations > 5_000_000) throw new Error("Invalid encrypted key parameters.");
    let keyLength = null;
    let hashName = "SHA-1";
    for (const parameter of kdfParameters.slice(2)) {
      if (parameter.tag === 0x02) keyLength = derIntegerValue(der, parameter);
      if (parameter.tag === 0x30) {
        const prf = derChildren(der, parameter);
        const oid = decodeOid(derContent(der, prf[0], 0x06));
        if (oid === "1.2.840.113549.2.9") hashName = "SHA-256";
        else if (oid !== "1.2.840.113549.2.7") throw new Error("This encrypted key format is not supported.");
      }
    }
    const encryption = derChildren(der, pbes2[1]);
    const cipherOid = decodeOid(derContent(der, encryption[0], 0x06));
    const cipherSizes = {
      "2.16.840.1.101.3.4.1.2": 16,
      "2.16.840.1.101.3.4.1.22": 24,
      "2.16.840.1.101.3.4.1.42": 32,
    };
    const size = cipherSizes[cipherOid];
    const iv = derContent(der, encryption[1], 0x04);
    if (!size || (keyLength !== null && keyLength !== size) || iv.length !== 16) throw new Error("This encrypted key format is not supported.");
    const passwordKey = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveBits"]);
    const keyBytes = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: hashName }, passwordKey, size * 8);
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-CBC", false, ["decrypt"]);
    try {
      return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, derContent(der, rootChildren[1], 0x04)));
    } catch {
      throw new Error("The private-key passphrase is incorrect, or the key is invalid.");
    }
  }

  function oidBytes(value) {
    const arcs = value.split(".").map(Number);
    const encoded = [];
    for (const arc of [arcs[0] * 40 + arcs[1], ...arcs.slice(2)]) {
      const parts = [arc & 0x7f];
      let rest = Math.floor(arc / 128);
      while (rest) {
        parts.unshift((rest & 0x7f) | 0x80);
        rest = Math.floor(rest / 128);
      }
      encoded.push(...parts);
    }
    return der(0x06, new Uint8Array(encoded));
  }

  function wrapPkcs1RsaKey(bytes, isPrivate) {
    const rsaAlgorithm = derSequence(oidBytes("1.2.840.113549.1.1.1"), der(0x05, new Uint8Array()));
    return isPrivate
      ? derSequence(derInteger(0), rsaAlgorithm, der(0x04, bytes))
      : derSequence(rsaAlgorithm, der(0x03, concatBytes(new Uint8Array([0]), bytes)));
  }

  function derLength(length) {
    if (length < 0x80) return new Uint8Array([length]);
    const parts = [];
    for (let value = length; value; value = Math.floor(value / 256)) parts.unshift(value & 0xff);
    return new Uint8Array([0x80 | parts.length, ...parts]);
  }

  function der(tag, content) {
    return concatBytes(new Uint8Array([tag]), derLength(content.length), content);
  }

  function derSequence(...items) {
    return der(0x30, concatBytes(...items));
  }

  function derInteger(value) {
    const bytes = [];
    for (let number = value; number; number = Math.floor(number / 256)) bytes.unshift(number & 0xff);
    if (!bytes.length) bytes.push(0);
    if (bytes[0] & 0x80) bytes.unshift(0);
    return der(0x02, new Uint8Array(bytes));
  }

  async function encryptedPkcs8(plainDer, passphrase) {
    if (!passphrase) return { label: "PRIVATE KEY", der: plainDer };
    const salt = randomBytes(16);
    const iv = randomBytes(16);
    const passwordKey = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveBits"]);
    const keyBytes = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, passwordKey, 256);
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-CBC", false, ["encrypt"]);
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, plainDer));
    const prf = derSequence(oidBytes("1.2.840.113549.2.9"), der(0x05, new Uint8Array()));
    const pbkdf2 = derSequence(oidBytes("1.2.840.113549.1.5.12"), derSequence(der(0x04, salt), derInteger(PBKDF2_ITERATIONS), derInteger(32), prf));
    const aes256 = derSequence(oidBytes("2.16.840.1.101.3.4.1.42"), der(0x04, iv));
    const pbes2 = derSequence(oidBytes("1.2.840.113549.1.5.13"), derSequence(pbkdf2, aes256));
    return { label: "ENCRYPTED PRIVATE KEY", der: derSequence(pbes2, der(0x04, encrypted)) };
  }

  async function importRsaKey(file, kind, passphrase = "") {
    if (!file || file.size > 64 * 1024) throw new Error(`Choose an RSA ${kind} PEM no larger than 64 KiB.`);
    const text = await file.text();
    const expectedLabel = kind === "public"
      ? text.includes("BEGIN RSA PUBLIC KEY") ? "RSA PUBLIC KEY" : "PUBLIC KEY"
      : text.includes("BEGIN ENCRYPTED PRIVATE KEY") ? "ENCRYPTED PRIVATE KEY"
        : text.includes("BEGIN RSA PRIVATE KEY") ? "RSA PRIVATE KEY" : "PRIVATE KEY";
    let derBytes = pemBytes(text, expectedLabel);
    if (kind === "private" && expectedLabel === "ENCRYPTED PRIVATE KEY") derBytes = await decryptEncryptedPkcs8(derBytes, passphrase);
    if (expectedLabel === "RSA PRIVATE KEY") derBytes = wrapPkcs1RsaKey(derBytes, true);
    if (expectedLabel === "RSA PUBLIC KEY") derBytes = wrapPkcs1RsaKey(derBytes, false);
    let key;
    try {
      key = await crypto.subtle.importKey(kind === "public" ? "spki" : "pkcs8", derBytes,
        { name: "RSA-OAEP", hash: "SHA-256" }, true, [kind === "public" ? "encrypt" : "decrypt"]);
      const jwk = await crypto.subtle.exportKey("jwk", key);
      const modulus = fromBase64(jwk.n.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((jwk.n.length + 3) % 4));
      const exponent = fromBase64(jwk.e.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((jwk.e.length + 3) % 4));
      if (modulus.length !== 256 || exponent.join(",") !== "1,0,1") throw new Error("CipherForge accepts RSA-2048 keys with public exponent 65537.");
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("CipherForge accepts")) throw error;
      throw new Error(`Choose a valid RSA-2048 ${kind} PEM using public exponent 65537.`);
    }
    return key;
  }

  async function encryptRsa(file, keyFile) {
    if (!file.size || file.size > 190) throw new Error("RSA-2048 with OAEP-SHA256 accepts at most 190 bytes.");
    if (Array.from(file.name).length > 255) throw new Error("The filename is too long.");
    const key = await importRsaKey(keyFile, "public");
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, await file.arrayBuffer()));
    const envelope = {
      format_version: 1,
      algorithm: "RSA-OAEP-SHA256",
      key_size: 2048,
      original_filename: file.name,
      mime_type: mimeTypeFor(file.name, file.type),
      ciphertext: base64(ciphertext),
    };
    return {
      blob: new Blob([encoder.encode(canonicalJson(envelope))], { type: "application/octet-stream" }),
      name: `${fileStem(file.name)}.encrypt.rsaenc`,
    };
  }

  async function decryptRsa(file, keyFile, passphrase) {
    if (!file.size || file.size > MAX_RSA_PACKAGE_BYTES) throw new Error("Choose a non-empty .rsaenc package within the 64 KiB limit.");
    let envelope;
    try {
      envelope = JSON.parse(decoder.decode(await file.arrayBuffer()));
    } catch {
      throw new Error("Could not decrypt this file. Check the private key and encrypted package.");
    }
    const fields = ["algorithm", "ciphertext", "format_version", "key_size", "mime_type", "original_filename"];
    if (!envelope || typeof envelope !== "object" || Array.isArray(envelope) || Object.keys(envelope).sort().join("\0") !== fields.join("\0") ||
        envelope.format_version !== 1 || envelope.algorithm !== "RSA-OAEP-SHA256" || envelope.key_size !== 2048 ||
        typeof envelope.original_filename !== "string" || !envelope.original_filename || Array.from(envelope.original_filename).length > 255 ||
        !(envelope.mime_type === null || (typeof envelope.mime_type === "string" && /^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/.test(envelope.mime_type)))) {
      throw new Error("Could not decrypt this file. Check the private key and encrypted package.");
    }
    try {
      const ciphertext = fromBase64(envelope.ciphertext);
      if (ciphertext.length !== 256) throw new Error();
      const key = await importRsaKey(keyFile, "private", passphrase);
      const plaintext = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, ciphertext);
      if (!plaintext.byteLength || plaintext.byteLength > 190) throw new Error();
      return {
        blob: new Blob([plaintext], { type: envelope.mime_type || "application/octet-stream" }),
        name: downloadedName(safeFilename(envelope.original_filename), "decrypt"),
      };
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("Choose a valid")) throw error;
      if (error instanceof Error && (error.message.startsWith("Enter the passphrase") || error.message.startsWith("The private-key passphrase") || error.message.startsWith("This encrypted key"))) throw error;
      throw new Error("Could not decrypt this file. The private key may not match, or the package may be invalid.");
    }
  }

  function crc32(bytes) {
    let crc = 0xffffffff;
    for (const byte of bytes) {
      crc ^= byte;
      for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
    return (crc ^ 0xffffffff) >>> 0;
  }

  function zipStored(files) {
    const localParts = [];
    const directoryParts = [];
    let offset = 0;
    for (const file of files) {
      const name = encoder.encode(file.name);
      const contents = file.contents;
      const crc = crc32(contents);
      const local = new Uint8Array(30 + name.length);
      const view = new DataView(local.buffer);
      view.setUint32(0, 0x04034b50, true);
      view.setUint16(4, 20, true);
      view.setUint16(6, 0x0800, true);
      view.setUint16(8, 0, true);
      view.setUint16(10, 0, true);
      view.setUint16(12, 0x0021, true);
      view.setUint32(14, crc, true);
      view.setUint32(18, contents.length, true);
      view.setUint32(22, contents.length, true);
      view.setUint16(26, name.length, true);
      local.set(name, 30);
      localParts.push(local, contents);

      const directory = new Uint8Array(46 + name.length);
      const central = new DataView(directory.buffer);
      central.setUint32(0, 0x02014b50, true);
      central.setUint16(4, 20, true);
      central.setUint16(6, 20, true);
      central.setUint16(8, 0x0800, true);
      central.setUint16(10, 0, true);
      central.setUint16(12, 0, true);
      central.setUint16(14, 0x0021, true);
      central.setUint32(16, crc, true);
      central.setUint32(20, contents.length, true);
      central.setUint32(24, contents.length, true);
      central.setUint16(28, name.length, true);
      central.setUint32(42, offset, true);
      directory.set(name, 46);
      directoryParts.push(directory);
      offset += local.length + contents.length;
    }
    const centralBytes = concatBytes(...directoryParts);
    const end = new Uint8Array(22);
    const endView = new DataView(end.buffer);
    endView.setUint32(0, 0x06054b50, true);
    endView.setUint16(8, files.length, true);
    endView.setUint16(10, files.length, true);
    endView.setUint32(12, centralBytes.length, true);
    endView.setUint32(16, offset, true);
    return new Blob([concatBytes(...localParts), centralBytes, end], { type: "application/zip" });
  }

  async function generateRsaKeyArchive(passphrase) {
    if (encoder.encode(passphrase).length > MAX_PASSWORD_BYTES) throw new Error("The private-key passphrase must be 1,024 UTF-8 bytes or fewer.");
    if (passphrase && !passphrase.trim()) throw new Error("The private-key passphrase cannot contain only spaces.");
    const pair = await crypto.subtle.generateKey({
      name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256",
    }, true, ["encrypt", "decrypt"]);
    const publicDer = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
    const privateDer = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    const privatePem = await encryptedPkcs8(privateDer, passphrase);
    const archive = zipStored([
      { name: "cipherforge-rsa-2048-public.pem", contents: encoder.encode(toPem("PUBLIC KEY", publicDer)) },
      { name: `cipherforge-rsa-2048-private.pem`, contents: encoder.encode(toPem(privatePem.label, privatePem.der)) },
    ]);
    return { blob: archive, name: "cipherforge-rsa-2048-key-pair.zip" };
  }

  async function processFile({ operation, algorithm, file, password, keyFile, keyPassphrase }) {
    const result = algorithm === "aes-cbc"
      ? operation === "encrypt" ? await encryptAes(file, password) : await decryptAes(file, password)
      : operation === "encrypt" ? await encryptRsa(file, keyFile) : await decryptRsa(file, keyFile, keyPassphrase);
    return result;
  }

  window.CipherForgeCrypto = { processFile, generateRsaKeyArchive };
})();
