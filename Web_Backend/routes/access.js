const express = require("express");
const { z } = require("zod");
const validate = require("../middleware/validate");
const { verifyAccessToken } = require("../middleware/auth");
const { appendAudit } = require("../services/audit");
const { generateApprovalId } = require("../services/crypto");
const { getDocument } = require("../services/documents");

const router = express.Router();

const accessSchema = z.object({
  body: z.object({
    documentId: z.string().uuid()
  })
});

router.post("/request", verifyAccessToken, validate(accessSchema), async (req, res) => {
  const { documentId } = req.validated.body;
  const document = await getDocument(documentId);

  if (!document) {
    return res.status(404).json({ message: "Document not found" });
  }

  const granted = req.user.clearanceLevel >= document.required_clearance;
  const approvalId = generateApprovalId();

  await appendAudit({
    user: req.user,
    action: "ACCESS_REQUEST",
    status: granted ? "GRANTED" : "DENIED",
    requiredClearance: document.required_clearance,
    documentId: document.id,
    metadata: { approvalId, filename: document.filename },
    approvalId
  });

  return res.json({
    granted,
    approvalId,
    requiredClearance: document.required_clearance,
    userClearance: req.user.clearanceLevel
  });
});

module.exports = router;
