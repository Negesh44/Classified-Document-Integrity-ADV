CREATE TABLE IF NOT EXISTS users (
  id CHAR(36) PRIMARY KEY,
  username VARCHAR(255) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role VARCHAR(32) NOT NULL,
  clearance_level INT NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id CHAR(36) PRIMARY KEY,
  user_id CHAR(36) NOT NULL,
  token_hash TEXT NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at TIMESTAMP NULL,
  CONSTRAINT fk_refresh_tokens_user_id FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS documents (
  id CHAR(36) PRIMARY KEY,
  filename TEXT NOT NULL,
  stored_path TEXT NOT NULL,
  mime_type VARCHAR(255) NOT NULL,
  size_bytes BIGINT NOT NULL,
  sha256 CHAR(64) NOT NULL,
  algorithm VARCHAR(20) NOT NULL DEFAULT 'SHA-256',
  required_clearance INT NOT NULL DEFAULT 2,
  status VARCHAR(32) NOT NULL DEFAULT 'REGISTERED',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_verified TIMESTAMP NULL,
  iv TEXT NOT NULL,
  auth_tag TEXT NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_ledger (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  `timestamp` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  user_id CHAR(36) NULL,
  username VARCHAR(255) NOT NULL,
  user_role VARCHAR(64) NOT NULL,
  clearance_level INT NOT NULL,
  action VARCHAR(64) NOT NULL,
  status VARCHAR(64) NOT NULL,
  approval_id VARCHAR(255) NOT NULL,
  required_clearance INT NULL,
  document_id CHAR(36) NULL,
  previous_hash TEXT NOT NULL,
  current_hash TEXT NOT NULL,
  metadata JSON NOT NULL,
  CONSTRAINT fk_audit_document_id FOREIGN KEY (document_id) REFERENCES documents(id)
) ENGINE=InnoDB;

CREATE INDEX idx_documents_sha256 ON documents (sha256);
CREATE INDEX idx_audit_ledger_timestamp ON audit_ledger (`timestamp` DESC);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
