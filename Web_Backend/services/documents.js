const fs = require("fs");
const path = require("path");
const db = require("../db");
const config = require("../config");
const { encryptBuffer, decryptBuffer, hashBuffer } = require("./crypto");

function formatMysqlDate(value) {
  return new Date(value).toISOString().slice(0, 19).replace("T", " ");
}

async function storeEncryptedDocument(buffer, metadata) {
  if (!fs.existsSync(config.secureStorageDir)) {
    fs.mkdirSync(config.secureStorageDir, { recursive: true });
  }

  const sha256 = hashBuffer(buffer);
  const encrypted = encryptBuffer(buffer);
  const fileId = cryptoRandomId();
  const storedPath = path.join(config.secureStorageDir, `${fileId}.enc`);

  fs.writeFileSync(storedPath, encrypted.encryptedBuffer);

  const documentId = cryptoRandomId();
  await db.query(
    "INSERT INTO documents (id, filename, stored_path, mime_type, size_bytes, sha256, required_clearance, status, last_verified, iv, auth_tag) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
    [
      documentId,
      metadata.filename,
      storedPath,
      metadata.mimeType,
      metadata.sizeBytes,
      sha256,
      metadata.requiredClearance,
      "REGISTERED",
      formatMysqlDate(new Date()),
      encrypted.iv,
      encrypted.authTag
    ]
  );

  const result = await db.query("SELECT * FROM documents WHERE id = ?", [documentId]);
  return result.rows[0];
}

async function verifyDocument(documentId) {
  const result = await db.query("SELECT * FROM documents WHERE id = ?", [documentId]);
  const document = result.rows[0];

  if (!document) {
    return { found: false };
  }

  const encryptedBuffer = fs.readFileSync(document.stored_path);
  const decrypted = decryptBuffer(encryptedBuffer, document.iv, document.auth_tag);
  const currentHash = hashBuffer(decrypted);
  const status = currentHash === document.sha256 ? "VERIFIED" : "COMPROMISED";

  await db.query(
    "UPDATE documents SET status = ?, last_verified = ? WHERE id = ?",
    [status, formatMysqlDate(new Date()), documentId]
  );

  const updated = await db.query("SELECT * FROM documents WHERE id = ?", [documentId]);
  return {
    found: true,
    status,
    currentHash,
    document: updated.rows[0]
  };
}

async function getDocument(documentId) {
  const result = await db.query("SELECT * FROM documents WHERE id = ?", [documentId]);
  return result.rows[0];
}

function cryptoRandomId() {
  return require("crypto").randomUUID();
}

module.exports = {
  storeEncryptedDocument,
  verifyDocument,
  getDocument
};
