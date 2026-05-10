# burps

A collection of Burp Suite extensions written in Python (Jython).

> **Authorised use only.** These extensions are intended for use during authorised security assessments only.

---

## Extensions

### BurpXHookSignature

A Burp Suite session handling action that automatically generates and injects an `X-Hook-Signature` header on every outgoing request.

**How it works:**

1. Extracts the raw request body
2. Concatenates the body to a shared secret key
3. Computes `Base64( SHA-512( key + body ) )`
4. Sets the result as the `X-Hook-Signature` header

This mirrors the signature scheme used by some webhook and API implementations that validate request integrity via a shared-secret HMAC header.

**Setup:**

1. In Burp Suite, go to **Extender → Extensions → Add**
2. Set **Extension type** to `Python`
3. Select `BurpXHookSignature/BurpXHookSignature.py`
4. Open the file and set `key = '<your shared secret>'` before loading

**Usage:**

In **Project options → Sessions → Session Handling Rules**, add a new rule and set the action to **Invoke a Burp extension** → `Bearer Authorization Token`.

> The extension logs each body, key, and computed hash to the Burp output tab for verification.

---

## Requirements

- Burp Suite (Community or Pro)
- [Jython standalone JAR](https://www.jython.org/download.html) configured in Extender options

---

## Roadmap

- [ ] Accept the shared secret via a UI tab rather than hardcoded in source
- [ ] Support configurable hash algorithm (SHA-256, SHA-512)
- [ ] Add additional extensions
