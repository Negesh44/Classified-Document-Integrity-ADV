const path = require("path");

require("dotenv").config();

const config = {
  port: process.env.PORT || 3000,
  jwtSecret: process.env.JWT_SECRET || "",
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || "",
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || "15m",
  jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d",
  encryptionKey: process.env.ENCRYPTION_KEY || "",
  uploadMaxBytes: parseInt(process.env.UPLOAD_MAX_BYTES || "20971520", 10),
  allowedMimeTypes: (process.env.ALLOWED_MIME_TYPES || "application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document").split(",").map((type) => type.trim()).filter(Boolean),
  secureStorageDir: path.join(__dirname, "secure_storage"),
  openAiApiKey: process.env.OPENAI_API_KEY || "",
  openAiModel: process.env.OPENAI_MODEL || "gpt-4o-mini",
  geminiApiKey: process.env.GEMINI_API_KEY || "",
  geminiModel: process.env.GEMINI_MODEL || "gemini-1.5-flash",
  dbHost: process.env.DB_HOST || "localhost",
  dbPort: parseInt(process.env.DB_PORT || "3306", 10),
  dbName: process.env.DB_NAME || "cdi_platform",
  dbUser: process.env.DB_USER || "root",
  dbPassword: process.env.DB_PASSWORD || ""
};

module.exports = config;
