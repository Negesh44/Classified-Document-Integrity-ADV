const express = require("express");
const { z } = require("zod");
const db = require("../db");
const validate = require("../middleware/validate");
const { verifyAccessToken, requireRole } = require("../middleware/auth");
const { verifyChain } = require("../services/audit");

const router = express.Router();

const listSchema = z.object({
  query: z.object({
    limit: z.coerce.number().min(1).max(500).optional()
  })
});

router.get("/ledger", verifyAccessToken, requireRole(["UNCLASSIFIED", "RESTRICTED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]), validate(listSchema), async (req, res) => {
  const limit = req.validated.query.limit || 200;
  const result = await db.query(
    "SELECT * FROM audit_ledger ORDER BY id DESC LIMIT ?",
    [limit]
  );
  return res.json({ chain: result.rows });
});

router.get("/verify", verifyAccessToken, requireRole(["TOP_SECRET"]), async (req, res) => {
  const result = await verifyChain();
  return res.json(result);
});

module.exports = router;
