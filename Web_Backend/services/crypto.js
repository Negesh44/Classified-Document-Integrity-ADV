const crypto = require("crypto");
const config = require("../config");

function loadKey() {
  if (!config.encryptionKey) {
    throw new Error("Missing ENCRYPTION_KEY");
  }

  if (/^[0-9a-fA-F]{64}$/.test(config.encryptionKey)) {
    return Buffer.from(config.encryptionKey, "hex");
  }

  return Buffer.from(config.encryptionKey, "base64");
}

function encryptBuffer(buffer) {
  const key = loadKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    encryptedBuffer: encrypted,
    iv: iv.toString("hex"),
    authTag: authTag.toString("hex")
  };
}

function decryptBuffer(encryptedBuffer, ivHex, authTagHex) {
  const key = loadKey();
  const iv = Buffer.from(ivHex, "hex");
  const authTag = Buffer.from(authTagHex, "hex");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
}

function hashBuffer(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function generateApprovalId() {
  return `APR-${crypto.randomInt(1000, 9999)}`;
}

module.exports = {
  encryptBuffer,
  decryptBuffer,
  hashBuffer,
  generateApprovalId
};
