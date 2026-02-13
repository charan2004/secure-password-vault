-- V1__Initial_Schema.sql

-- Users Table
CREATE TABLE users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    mfa_secret VARCHAR(255),
    mfa_enabled BOOLEAN DEFAULT TRUE,
    roles VARCHAR(255)[] -- Stores roles as an array of strings
);

-- User Keys Table (Envelope Encryption)
CREATE TABLE user_keys (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    encrypted_dek BYTEA NOT NULL,
    kek_salt BYTEA NOT NULL,
    kek_iv BYTEA NOT NULL
);

-- Vault Entries Table
CREATE TABLE vault_entries (
    id UUID PRIMARY KEY,
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_data BYTEA NOT NULL,
    iv BYTEA NOT NULL,
    aad BYTEA,
    version INT DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit Logs Table
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor_id UUID NOT NULL,
    action VARCHAR(255) NOT NULL,
    details TEXT,
    integrity_hash VARCHAR(64) NOT NULL, -- SHA-256 Hex
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_integrity ON audit_logs(id, integrity_hash);
