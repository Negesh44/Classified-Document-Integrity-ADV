const express = require("express");
const config = require("../config");
const db = require("../db");
const { verifyAccessToken } = require("../middleware/auth");

const router = express.Router();

function buildRuleSummary(metrics) {
  const parts = [];
  if (metrics.compromisedDocs > 0) {
    parts.push("Compromised documents detected.");
  }
  if (metrics.deniedAccess24h > 0) {
    parts.push(`Denied access attempts in last 24h: ${metrics.deniedAccess24h}.`);
  }
  if (!parts.length) {
    parts.push("No unusual access patterns detected in the last 24h.");
  }
  return parts.join(" ");
}

function computeRisk(metrics) {
  let score = 0;
  if (metrics.deniedAccess24h >= 5) score += 2;
  if (metrics.deniedAccess24h >= 20) score += 2;
  if (metrics.compromisedDocs > 0) score += 5;
  if (metrics.verifyFailures24h > 0) score += 3;

  if (score >= 6) return { level: "High", score };
  if (score >= 3) return { level: "Medium", score };
  return { level: "Low", score };
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
        temperature: 0.2
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

router.get("/summary", verifyAccessToken, async (req, res) => {
  try {
    const deniedAccess = await db.query(
      "SELECT COUNT(*) AS total FROM audit_ledger WHERE action = 'ACCESS_REQUEST' AND status = 'DENIED' AND `timestamp` >= (NOW() - INTERVAL 1 DAY)"
    );
    const accessRequests = await db.query(
      "SELECT COUNT(*) AS total FROM audit_ledger WHERE action = 'ACCESS_REQUEST' AND `timestamp` >= (NOW() - INTERVAL 1 DAY)"
    );
    const verifyFailures = await db.query(
      "SELECT COUNT(*) AS total FROM audit_ledger WHERE action = 'VERIFY' AND status = 'COMPROMISED' AND `timestamp` >= (NOW() - INTERVAL 1 DAY)"
    );
    const compromisedDocs = await db.query(
      "SELECT COUNT(*) AS total FROM documents WHERE status = 'COMPROMISED'"
    );

    const metrics = {
      deniedAccess24h: Number(deniedAccess.rows[0].total || 0),
      accessRequests24h: Number(accessRequests.rows[0].total || 0),
      verifyFailures24h: Number(verifyFailures.rows[0].total || 0),
      compromisedDocs: Number(compromisedDocs.rows[0].total || 0)
    };

    const risk = computeRisk(metrics);
    let summary = buildRuleSummary(metrics);
    let mode = "rule";

    if (config.geminiApiKey) {
      try {
        const systemPrompt = [
          "You are a security analyst for a classified document system.",
          "Provide a short threat summary and one recommended action.",
          "Keep it concise and non-alarming unless risk is high."
        ].join(" ");

        const contents = [
          {
            role: "user",
            parts: [
              { text: systemPrompt },
              { text: JSON.stringify({ metrics, risk }) }
            ]
          }
        ];

        summary = await callGemini(contents);
        mode = "ai";
      } catch (error) {
        summary = buildRuleSummary(metrics);
        mode = "rule";
      }
    }

    return res.json({
      status: risk.level,
      score: risk.score,
      summary,
      metrics,
      mode
    });
  } catch (error) {
    return res.status(500).json({ message: error.message || "Threat summary error" });
  }
});

module.exports = router;
