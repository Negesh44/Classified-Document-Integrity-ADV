const express = require("express");
const { z } = require("zod");
const config = require("../config");
const db = require("../db");
const validate = require("../middleware/validate");
const { verifyAccessToken } = require("../middleware/auth");

const router = express.Router();

const chatSchema = z.object({
  body: z.object({
    question: z.string().min(2),
    documentId: z.string().uuid().optional()
  })
});

const clearanceMap = {
  UNCLASSIFIED: 1,
  RESTRICTED: 2,
  CONFIDENTIAL: 3,
  SECRET: 4,
  TOP_SECRET: 5
};

function buildAccessContext(user, document) {
  const userClearance = user && user.clearanceLevel ? user.clearanceLevel : 0;
  const requiredClearance = document ? document.required_clearance : null;
  const accessAllowed = document ? userClearance >= requiredClearance : null;

  const clearanceLevels = [1, 2, 3, 4, 5];
  const allowedLevels = requiredClearance
    ? clearanceLevels.filter((level) => level >= requiredClearance)
    : [];

  return {
    user: {
      username: user && user.username,
      role: user && user.role,
      clearanceLevel: userClearance
    },
    document: document
      ? {
          id: document.id,
          filename: document.filename,
          status: document.status,
          requiredClearance
        }
      : null,
    accessRule: "Users can access a document if their clearanceLevel is >= required_clearance.",
    allowedLevels,
    accessAllowed
  };
}

function formatClearanceList(levels) {
  if (!levels.length) {
    return "none";
  }
  return levels.join(", ");
}

function buildRuleAnswer(question, context) {
  const normalized = question.toLowerCase();
  const document = context.document;

  if (!document) {
    return "Which document? Please select a document first.";
  }

  const required = document.requiredClearance;
  const allowedLevels = context.allowedLevels;
  const userClearance = context.user.clearanceLevel;
  const accessAllowed = context.accessAllowed;

  if (normalized.includes("who") || normalized.includes("access") || normalized.includes("can")) {
    return [
      `Allowed clearance levels: ${formatClearanceList(allowedLevels)} (>= ${required}).`,
      `User clearance: ${userClearance}. Access: ${accessAllowed ? "Allowed" : "Denied"}.`,
      "Access is allowed when clearance >= required level."
    ].join(" ");
  }

  if (normalized.includes("priority") || normalized.includes("clearance") || normalized.includes("level")) {
    return [
      `Document required clearance: ${required}.`,
      `Allowed: ${formatClearanceList(allowedLevels)}.`,
      "Required clearance must be met or exceeded."
    ].join(" ");
  }

  return [
    "Ask about access or clearance level for the selected document.",
    "Try: Who can access this document?"
  ].join(" ");
}

async function callGemini(contents) {
  if (!config.geminiApiKey) {
    throw new Error("Missing GEMINI_API_KEY");
  }

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${config.geminiModel}:generateContent?key=${config.geminiApiKey}`;
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      contents,
      generationConfig: {
        temperature: 0.3
      }
    })
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || "Gemini request failed");
  }

  const data = await response.json();
  const parts = data.candidates && data.candidates[0] && data.candidates[0].content
    ? data.candidates[0].content.parts
    : [];
  return parts.map((part) => part.text || "").join("").trim() || "No response";
}

router.post("/", verifyAccessToken, validate(chatSchema), async (req, res) => {
  try {
    const { question, documentId } = req.validated.body;

    let document = null;
    if (documentId) {
      const result = await db.query(
        "SELECT id, filename, status, required_clearance, size_bytes, mime_type, created_at, last_verified FROM documents WHERE id = ?",
        [documentId]
      );
      document = result.rows[0];
      if (!document) {
        return res.status(404).json({ message: "Document not found" });
      }
    }

    const context = buildAccessContext(req.user, document);
    if (document) {
      context.document.sizeBytes = document.size_bytes;
      context.document.mimeType = document.mime_type;
      context.document.createdAt = document.created_at;
      context.document.lastVerified = document.last_verified;
    }

    if (!config.geminiApiKey) {
      const answer = buildRuleAnswer(question, context);
      return res.json({ answer, context, mode: "rule" });
    }

    const systemPrompt = [
      "You are an access assistant for a classified document system.",
      "Answer questions about access, clearance, and document metadata.",
      "Use the access rule: clearanceLevel >= required_clearance.",
      "If document info is missing, ask which document the user means.",
      "Do not reveal passwords or secrets.",
      "Keep responses concise."
    ].join(" ");

    const contents = [
      {
        role: "user",
        parts: [
          { text: systemPrompt },
          { text: JSON.stringify({ question, context, clearanceMap }) }
        ]
      }
    ];

    const answer = await callGemini(contents);
    return res.json({ answer, context, mode: "ai" });
  } catch (error) {
    const fallback = buildRuleAnswer(req.validated.body.question, buildAccessContext(req.user, null));
    return res.status(500).json({
      message: error.message || "Chat error",
      fallback
    });
  }
});

module.exports = router;
