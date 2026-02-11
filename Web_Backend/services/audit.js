const db = require("../db");
const { generateApprovalId, hashBuffer } = require("./crypto");

function formatMysqlDate(value) {
  return new Date(value).toISOString().slice(0, 19).replace("T", " ");
}

function stableStringify(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }

  const keys = Object.keys(value).sort();
  const pairs = keys.map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`);
  return `{${pairs.join(",")}}`;
}

function safeParseJson(value) {
  if (typeof value !== "string") {
    return value;
  }

  try {
    return JSON.parse(value);
  } catch (error) {
    return {};
  }
}

function buildAuditHash(block) {
  const payload = [
    block.index,
    block.timestamp,
    block.user_id || "",
    block.username,
    block.user_role,
    block.clearance_level,
    block.action,
    block.status,
    block.approval_id,
    block.required_clearance || "",
    block.document_id || "",
    block.previous_hash,
    stableStringify(block.metadata || {})
  ].join("|");

  return hashBuffer(Buffer.from(payload));
}

async function getLastAudit() {
  const result = await db.query("SELECT * FROM audit_ledger ORDER BY id DESC LIMIT 1");
  return result.rows[0];
}

async function appendAudit({ user, action, status, requiredClearance, documentId, metadata, approvalId }) {
  const last = await getLastAudit();
  const previousHash = last ? last.current_hash : "0000000000000000";
  const finalApprovalId = approvalId || generateApprovalId();
  const timestamp = formatMysqlDate(new Date());

  const block = {
    index: last ? last.id + 1 : 1,
    timestamp,
    user_id: user ? user.id : null,
    username: user ? user.username : "system",
    user_role: user ? user.role : "SYSTEM",
    clearance_level: user ? user.clearanceLevel : 0,
    action,
    status,
    approval_id: finalApprovalId,
    required_clearance: requiredClearance || null,
    document_id: documentId || null,
    previous_hash: previousHash,
    metadata: metadata || {}
  };

  const currentHash = buildAuditHash(block);

  const insert = await db.query(
    "INSERT INTO audit_ledger (`timestamp`, user_id, username, user_role, clearance_level, action, status, approval_id, required_clearance, document_id, previous_hash, current_hash, metadata) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
    [
      block.timestamp,
      block.user_id,
      block.username,
      block.user_role,
      block.clearance_level,
      block.action,
      block.status,
      block.approval_id,
      block.required_clearance,
      block.document_id,
      block.previous_hash,
      currentHash,
      JSON.stringify(block.metadata)
    ]
  );

  const result = await db.query("SELECT * FROM audit_ledger WHERE id = ?", [insert.insertId]);
  return result.rows[0];
}

async function verifyChain() {
  const result = await db.query("SELECT * FROM audit_ledger ORDER BY id ASC");
  const rows = result.rows;

  for (let i = 0; i < rows.length; i += 1) {
    const block = rows[i];
    const expectedPrevious = i === 0 ? "0000000000000000" : rows[i - 1].current_hash;

    const rawMetadata = safeParseJson(block.metadata);
    const reconstructed = {
      index: block.id,
      timestamp: new Date(block.timestamp).toISOString(),
      user_id: block.user_id,
      username: block.username,
      user_role: block.user_role,
      clearance_level: block.clearance_level,
      action: block.action,
      status: block.status,
      approval_id: block.approval_id,
      required_clearance: block.required_clearance,
      document_id: block.document_id,
      previous_hash: block.previous_hash,
      metadata: rawMetadata || {}
    };

    const expectedHash = buildAuditHash(reconstructed);

    if (block.previous_hash !== expectedPrevious || block.current_hash !== expectedHash) {
      return {
        valid: false,
        failedAt: block.id
      };
    }
  }

  return {
    valid: true,
    length: rows.length
  };
}

module.exports = {
  appendAudit,
  verifyChain
};
