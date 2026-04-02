# rpgp-py

Python bindings for [`rpgp`](https://github.com/rpgp/rpgp), exposed as the `openpgp` Python package.

## Install

```bash
uv sync
```

## Build the extension locally

```bash
uv run maturin develop
```

## Example

```python
from openpgp import (
    CleartextSignedMessage,
    DetachedSignature,
    Message,
    PublicKey,
    SecretKey,
    SignatureInfo,
    encrypt_message_to_recipient,
    encrypt_message_with_password,
    sign_cleartext_message,
    sign_message,
)

public_key, _ = PublicKey.from_armor(public_key_armor)
public_key.verify_bindings()

secret_key, _ = SecretKey.from_armor(secret_key_armor)
assert secret_key.to_public_key().fingerprint == public_key.fingerprint

signed_message = sign_message(b"hello world", secret_key)
message, _ = Message.from_armor(signed_message)
message.verify(public_key)
assert message.payload_text() == "hello world"

signature = DetachedSignature.sign_binary(b"hello world", secret_key)
info = signature.signature_info()
assert info.signature_type == "binary"
signature.verify(public_key, b"hello world")

cleartext = sign_cleartext_message("hello\n-world\n", secret_key)
cleartext_message, _ = CleartextSignedMessage.from_armor(cleartext)
assert "Hash: SHA256" in cleartext
assert cleartext_message.signed_text() == "hello\r\n-world\r\n"
assert cleartext_message.signature_count() == 1
assert cleartext_message.signature_infos()[0].hash_algorithm == "SHA256"

password_encrypted = encrypt_message_with_password(b"secret", "hunter2")
encrypted_message, _ = Message.from_armor(password_encrypted)
decrypted = encrypted_message.decrypt_with_password("hunter2")
assert decrypted.payload_text() == "secret"

recipient_encrypted = encrypt_message_to_recipient(b"secret", public_key)
recipient_message, _ = Message.from_armor(recipient_encrypted)
recipient_decrypted = recipient_message.decrypt(secret_key)
assert recipient_decrypted.payload_bytes() == b"secret"
assert recipient_decrypted.signature_infos() == []

# Existing encrypted-and-signed messages can still be inspected and verified after decryption.
encrypted_signed_message, _ = Message.from_armor(encrypted_signed_armor)
decrypted_signed = encrypted_signed_message.decrypt(secret_key)
assert decrypted_signed.signature_count() == 1
decrypted_signed.verify(public_key)
```

## Current binding surface

- Parse ASCII-armored or binary transferable public keys.
- Parse ASCII-armored or binary transferable secret keys.
- Expose key metadata such as fingerprints, key IDs, subkey counts, and user IDs.
- Serialize keys back to binary packets or ASCII armor.
- Parse OpenPGP messages into reusable Python `Message` objects.
- Inspect top-level message metadata and read signed, literal, or compressed payloads.
- Decrypt encrypted messages to `DecryptedMessage` results using a secret key or password.
- Continue inspecting or verifying nested signed payloads after decryption through the same signature helpers exposed on `Message`.
- Create password-encrypted or recipient-encrypted OpenPGP messages.
- Parse, serialize, create, and verify detached signatures.
- Inspect detached, inline, and cleartext signature packet metadata through `SignatureInfo`.
- Create simple signed OpenPGP messages with `sign_message(...)`.
- Introspect and selectively verify multi-signed inline messages, including one-pass signatures.
- Parse, create, serialize, and verify cleartext signed messages, including messages with multiple signatures.
- Verify key self-signatures and bindings.
- Convert a parsed secret key to its public-key view.
- Inspect whether OpenPGP message data is literal, compressed, signed, or encrypted.
