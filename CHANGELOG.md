# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-02-13

### Added
- **Core Security**:
  - Implemented Argon2id for secure password hashing (memory-hard, GPU-resistant).
  - Implemented AES-256-GCM for vault entry encryption with unique IVs.
  - Secure random number generation using `SecureRandom`.
  - In-memory key management for CLI session.

- **Authentication & MFA**:
  - User registration and login workflow.
  - Role-Based Access Control (RBAC) with `ADMIN`, `USER`, and `READ_ONLY` roles.
  - Time-based One-Time Password (TOTP) MFA (RFC 6238 compliant).
  - QR Code generation for easy authenticator app enrollment.
  - Rate limiting (5 failed attempts locks account for 15 minutes).
  - Secure session management with auto-expiry.

- **Vault Management**:
  - Encrypted storage for vault entries (title, username, password, notes).
  - RBAC enforcement:
    - Admins can manage all entries.
    - Users can manage their own entries.
    - Read-only users can view but not edit/delete.
  - CRUD operations (Create, Read, Update, Delete).

- **Audit & Compliance**:
  - Tamper-evident audit logging using SHA-256 hash chaining.
  - Logs for all security-critical events (login, MFA failure, vault access).
  - Immutable log history.

- **CLI Interface**:
  - Interactive command-line interface.
  - Commands: `register`, `login`, `add`, `list`, `view`, `edit`, `delete`, `logout`.
  - Secure input handling (passwords not echoed where supported).

- **Database**:
  - PostgreSQL schema with Flyway migrations.
  - Tables: `users`, `vault_entries`, `audit_logs`.
  - Foreign key constraints and indexes for performance.
