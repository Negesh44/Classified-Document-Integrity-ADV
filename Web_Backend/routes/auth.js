const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { z } = require("zod");
const { randomUUID } = require("crypto");
const db = require("../db");
const config = require("../config");
const validate = require("../middleware/validate");
const { verifyAccessToken, requireRole } = require("../middleware/auth");

const router = express.Router();

function formatMysqlDate(value) {
  return new Date(value).toISOString().slice(0, 19).replace("T", " ");
}


const loginSchema = z.object({
  body: z.object({
    username: z.string().min(3),
    password: z.string().min(8)
  })
});

const refreshSchema = z.object({
  body: z.object({
    refreshToken: z.string().min(10)
  })
});

const createUserSchema = z.object({
  body: z.object({
    username: z.string().min(3),
    password: z.string().min(8),
    role: z.enum(["UNCLASSIFIED", "RESTRICTED", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]),
    clearanceLevel: z.number().min(1).max(5).optional()
  })
});

const roleToClearance = {
  UNCLASSIFIED: 1,
  RESTRICTED: 2,
  CONFIDENTIAL: 3,
  SECRET: 4,
  TOP_SECRET: 5
};

function signAccessToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      username: user.username,
      role: user.role,
      clearanceLevel: user.clearance_level
    },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );
}

function signRefreshToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      username: user.username
    },
    config.jwtRefreshSecret,
    { expiresIn: config.jwtRefreshExpiresIn }
  );
}

function hashToken(token) {
  return require("crypto").createHash("sha256").update(token).digest("hex");
}


router.post("/login", validate(loginSchema), async (req, res) => {
  const { username, password } = req.validated.body;
  const result = await db.query("SELECT * FROM users WHERE username = ?", [username]);
  const user = result.rows[0];

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);
  const refreshHash = hashToken(refreshToken);
  const decoded = jwt.decode(refreshToken);
  const expiresAt = formatMysqlDate(decoded.exp * 1000);

  await db.query(
    "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?,?,?,?)",
    [randomUUID(), user.id, refreshHash, expiresAt]
  );

  return res.json({
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      clearanceLevel: user.clearance_level
    }
  });
});

router.post("/refresh", validate(refreshSchema), async (req, res) => {
  const { refreshToken } = req.validated.body;

  try {
    const payload = jwt.verify(refreshToken, config.jwtRefreshSecret);
    const tokenHash = hashToken(refreshToken);
    const existing = await db.query(
      "SELECT * FROM refresh_tokens WHERE token_hash = ? AND revoked_at IS NULL",
      [tokenHash]
    );

    if (existing.rows.length === 0) {
      return res.status(401).json({ message: "Refresh token revoked" });
    }

    await db.query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = ?", [tokenHash]);

    const userResult = await db.query("SELECT * FROM users WHERE id = ?", [payload.sub]);
    const user = userResult.rows[0];

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    const newAccessToken = signAccessToken(user);
    const newRefreshToken = signRefreshToken(user);
    const newHash = hashToken(newRefreshToken);
    const decoded = jwt.decode(newRefreshToken);
    const expiresAt = formatMysqlDate(decoded.exp * 1000);

    await db.query(
      "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES (?,?,?,?)",
      [randomUUID(), user.id, newHash, expiresAt]
    );

    return res.json({ accessToken: newAccessToken, refreshToken: newRefreshToken });
  } catch (error) {
    return res.status(401).json({ message: "Invalid refresh token" });
  }
});

router.post("/logout", validate(refreshSchema), async (req, res) => {
  const { refreshToken } = req.validated.body;
  const tokenHash = hashToken(refreshToken);
  await db.query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = ?", [tokenHash]);
  return res.json({ message: "Logged out" });
});

router.post("/users", verifyAccessToken, requireRole(["TOP_SECRET"]), validate(createUserSchema), async (req, res) => {
  const { username, password, role } = req.validated.body;
  const clearanceLevel = roleToClearance[role] || 1;
  const existing = await db.query("SELECT id FROM users WHERE username = ?", [username]);

  if (existing.rows.length > 0) {
    return res.status(409).json({ message: "Username already exists" });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const userId = randomUUID();
  await db.query(
    "INSERT INTO users (id, username, password_hash, role, clearance_level) VALUES (?,?,?,?,?)",
    [userId, username, passwordHash, role, clearanceLevel]
  );
  const result = await db.query("SELECT * FROM users WHERE id = ?", [userId]);

  return res.json({
    user: {
      id: result.rows[0].id,
      username: result.rows[0].username,
      role: result.rows[0].role,
      clearanceLevel: result.rows[0].clearance_level
    }
  });
});

module.exports = router;
