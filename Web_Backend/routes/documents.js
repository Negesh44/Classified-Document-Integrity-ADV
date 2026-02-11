const express = require("express");
const multer = require("multer");
const { z } = require("zod");
const config = require("../config");
const validate = require("../middleware/validate");
const { verifyAccessToken, requireClearance } = require("../middleware/auth");
const { storeEncryptedDocument, verifyDocument, getDocument } = require("../services/documents");
const { appendAudit } = require("../services/audit");
const { decryptBuffer } = require("../services/crypto");
const db = require("../db");
const fs = require("fs");

const router = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: config.uploadMaxBytes
  },
  fileFilter: (req, file, cb) => {
    if (!config.allowedMimeTypes.includes(file.mimetype)) {
      return cb(new Error("File type not allowed"));
    }
    return cb(null, true);
  }
});

const uploadSchema = z.object({
  body: z.object({
    requiredClearance: z.coerce.number().min(1).max(5).optional()
  })
});

router.post("/upload", verifyAccessToken, upload.single("document"), validate(uploadSchema), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ message: "No file uploaded" });
  }

  const requiredClearance = req.validated.body.requiredClearance || 2;

  const document = await storeEncryptedDocument(req.file.buffer, {
    filename: req.file.originalname,
    mimeType: req.file.mimetype,
    sizeBytes: req.file.size,
    requiredClearance
  });

  await appendAudit({
    user: req.user,
    action: "UPLOAD",
    status: "REGISTERED",
    requiredClearance,
    documentId: document.id,
    metadata: { filename: document.filename }
  });

  return res.json({
    message: "Document uploaded",
    document
  });
});

router.get("/", verifyAccessToken, async (req, res) => {
  const result = await db.query(
    "SELECT id, filename, mime_type, size_bytes, sha256, status, required_clearance, created_at, last_verified FROM documents ORDER BY created_at DESC"
  );
  return res.json({ documents: result.rows });
});

router.get("/:id", verifyAccessToken, async (req, res) => {
  const document = await getDocument(req.params.id);
  if (!document) {
    return res.status(404).json({ message: "Document not found" });
  }

  return res.json({
    document: {
      id: document.id,
      filename: document.filename,
      mime_type: document.mime_type,
      size_bytes: document.size_bytes,
      sha256: document.sha256,
      status: document.status,
      required_clearance: document.required_clearance,
      created_at: document.created_at,
      last_verified: document.last_verified
    }
  });
});

router.post("/:id/verify", verifyAccessToken, async (req, res) => {
  const result = await verifyDocument(req.params.id);
  if (!result.found) {
    return res.status(404).json({ message: "Document not found" });
  }

  await appendAudit({
    user: req.user,
    action: "VERIFY",
    status: result.status,
    requiredClearance: result.document.required_clearance,
    documentId: result.document.id,
    metadata: { filename: result.document.filename }
  });

  return res.json({
    message: "Verification complete",
    status: result.status,
    currentHash: result.currentHash,
    document: result.document
  });
});

router.get("/:id/download", verifyAccessToken, requireClearance(2), async (req, res) => {
  const document = await getDocument(req.params.id);
  if (!document) {
    return res.status(404).json({ message: "Document not found" });
  }

  if (req.user.clearanceLevel < document.required_clearance) {
    return res.status(403).json({ message: "Insufficient clearance" });
  }

  const encryptedBuffer = fs.readFileSync(document.stored_path);
  const decrypted = decryptBuffer(encryptedBuffer, document.iv, document.auth_tag);

  res.setHeader("Content-Type", document.mime_type);
  res.setHeader("Content-Disposition", `attachment; filename=\"${document.filename}\"`);
  return res.send(decrypted);
});

module.exports = router;
