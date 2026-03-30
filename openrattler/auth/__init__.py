"""Authentication credential managers for OpenRattler external service integrations.

This package handles OAuth 2.0 token acquisition, encrypted storage at rest,
and automatic silent refresh for Google APIs (Gmail, Drive, Calendar) and any
future OAuth-based integrations.

SECURITY DESIGN
---------------
- Tokens are never stored in plaintext on disk (Fernet + PBKDF2HMAC).
- Passphrases are resolved from environment variables first so that automated
  restarts (cron, scheduled tasks) work without interactive prompts.
- Passphrases are never stored as instance state; they are resolved on each
  encrypt/decrypt call and immediately discarded.
- Revocation deletes the local token file and calls the provider's revocation
  endpoint so stolen tokens cannot be replayed.
"""
