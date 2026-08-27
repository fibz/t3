# MFA Methods — Phased Rollout

**Status:** Planning
**Phase 1 (Current):** Google Authenticator (TOTP)
**Future Phases:** Passkeys/WebAuthn, hardware tokens, other TOTP apps

---

## Phase 1: Google Authenticator (TOTP)

### What It Is
Time-based One-Time Password (TOTP) — shared secret generates 6-digit code every 30 seconds.

### Implementation
- **Library:** `otplib` (Node.js)
- **QR Generation:** `qrcode` library
- **Storage:** `users.mfa_secret` (base32 string)
- **Flow:** 
  1. Registration: generate secret → show QR → user scans → verify code → save
  2. Login: password OK → pending MFA challenge → user enters code → verify → session

### Pros
- Simple, well-understood
- Works offline
- No infrastructure beyond QR generation
- Compatible with any TOTP app (Google Auth, Authy, Microsoft Auth, etc.)

### Cons
- User must manually type code
- Secret can be phished (though TOTP is more resistant than SMS)
- Lost device = recovery workflow (no backup codes in our model)

### Architecture Notes
- `users.mfa_secret` — TOTP secret (base32)
- `users.mfa_enabled` — always true (mandatory policy)
- `mfa_pending` table — time-limited challenge (30-60 min)

---

## Phase 2: Passkeys / WebAuthn (Placeholder)

### What It Is
Public-key cryptography tied to device. User authenticates with biometrics (Face ID, Touch ID, Windows Hello) or device PIN.

### Future Implementation
- **Library:** `@simplewebauthn/server` (Node.js)
- **Storage:** `users.passkey_credential_id`, `users.passkey_public_key`
- **Flow:**
  1. Registration: generate challenge → user creates passkey → store credential
  2. Login: password OK → pending MFA → user authenticates with passkey → verify signature → session

### Pros
- Phishing-resistant
- No shared secret (can't be phished)
- Modern UX (biometric unlock)
- Passwordless option (future)

### Cons
- Newer standard, browser support still maturing
- Device-bound (lose device = recovery workflow)
- More complex implementation

### Architecture Notes (Placeholder)
- Add to `users` table:
  - `passkey_credential_id` VARCHAR
  - `passkey_public_key` TEXT (or JSONB)
  - `passkey_registered_at` BIGINT
- New table `passkey_challenges` for WebAuthn challenge/response
- Same `mfa_pending` flow, different verification method

### Compatibility
- Can coexist with TOTP (user chooses method)
- Same recovery flow (proof-of-person) works for both

---

## Phase 3: Hardware Tokens (Placeholder)

### What It Is
Physical device (YubiKey, Titan) that signs challenge with private key. FIDO2/U2F protocol.

### Future Implementation
- **Library:** Same as passkeys (`@simplewebauthn/server`)
- **Storage:** Same as passkeys (credential ID + public key)
- **Flow:** Same as passkeys, but user must physically touch device

### Pros
- Strongest security
- Phishing-resistant
- Works across services

### Cons
- User must carry device
- Costs money
- Lost device = recovery workflow

### Architecture Notes (Placeholder)
- Same schema as passkeys (WebAuthn covers both)
- May need `hardware_token_type` column (YubiKey vs Titan vs other)

---

## Future Methods (Not Planned Yet)

| Method | Notes |
|--------|-------|
| Other TOTP apps (Authy, Microsoft Auth) | Already compatible with Phase 1 (same TOTP protocol) |
| Push notifications | Requires push infra (FCM/APNs), MFA fatigue risk |
| SMS/email OTP | Weak security, avoid for mandatory MFA |
| Biometrics (standalone) | Not portable, privacy issues, usually combined with other factors |

---

## Migration Path (Phase 1 → Phase 2/3)

### Database Changes
```sql
-- Add to users table
ALTER TABLE users ADD COLUMN passkey_credential_id VARCHAR(255);
ALTER TABLE users ADD COLUMN passkey_public_key TEXT;
ALTER TABLE users ADD COLUMN passkey_registered_at BIGINT;

-- Or use JSONB for multiple passkeys
ALTER TABLE users ADD COLUMN passkeys JSONB; -- Array of {credential_id, public_key, registered_at}
```

### Code Changes
- `src/auth/mfa/totp.js` — Phase 1 implementation
- `src/auth/mfa/passkey.js` — Phase 2 implementation (future)
- `src/auth/mfa/hardware-token.js` — Phase 3 implementation (future)
- User settings page: choose MFA method (TOTP / Passkey / Hardware)
- Same `mfa_pending` challenge table, different verification logic

### User Experience
- User can register multiple methods (e.g., TOTP + passkey)
- Login flow: password → choose method → verify → session
- Recovery flow: same for all methods (proof-of-person)

---

## Current Status

**Phase 1 (Google Authenticator / TOTP):** Ready to build
- Dependencies: `otplib`, `qrcode`
- Schema: already has `mfa_secret`, `mfa_enabled`, `mfa_pending` table
- Flow: documented in `mfa-decisions.md`

**Phase 2 (Passkeys):** Placeholder only
- No implementation yet
- Schema placeholder defined
- Will add when Phase 1 is stable

**Phase 3 (Hardware Tokens):** Placeholder only
- No implementation yet
- Uses same WebAuthn protocol as passkeys
- Will add when Phase 2 is stable
