const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcryptjs");
const { randomUUID } = require("crypto");
const db = require("./db");
const config = require("./config");
const { authLimiter, apiLimiter } = require("./middleware/rateLimit");
const authRoutes = require("./routes/auth");
const documentRoutes = require("./routes/documents");
const accessRoutes = require("./routes/access");
const auditRoutes = require("./routes/audit");
const chatRoutes = require("./routes/chat");
const threatRoutes = require("./routes/threats");

const app = express();

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"] ,
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"]
      }
    }
  })
);
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(apiLimiter);

if (!config.jwtSecret || !config.jwtRefreshSecret) {
  console.warn("JWT secrets are missing. Set JWT_SECRET and JWT_REFRESH_SECRET in .env");
}

if (!config.encryptionKey) {
  console.warn("ENCRYPTION_KEY is missing. Document encryption will fail until set.");
}

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.use("/auth", authLimiter, authRoutes);
app.use("/documents", documentRoutes);
app.use("/access", accessRoutes);
app.use("/audit", auditRoutes);
app.use("/chat", chatRoutes);
app.use("/threats", threatRoutes);

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/app", (req, res) => {
  res.sendFile(path.join(__dirname, "app.html"));
});

async function ensureDefaultAdmin() {
  const result = await db.query("SELECT id FROM users WHERE username = ?", ["admin"]);
  if (result.rows.length > 0) {
    return;
  }

  const passwordHash = await bcrypt.hash("admin12345678", 12);
  await db.query(
    "INSERT INTO users (id, username, password_hash, role, clearance_level) VALUES (?,?,?,?,?)",
    [randomUUID(), "admin", passwordHash, "TOP_SECRET", 5]
  );
  console.log("Default admin seeded: admin / admin12345678");
}

app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.message);
  res.status(500).json({ message: err.message || "Internal server error" });
});

app.listen(config.port, async () => {
  await ensureDefaultAdmin();
  console.log("Classified Document Integrity Platform");
  console.log(`Server running at http://localhost:${config.port}`);
});