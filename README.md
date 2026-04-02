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
from openpgp import DetachedSignature, Message, PublicKey, SecretKey, sign_message

public_key, headers = PublicKey.from_armor(public_key_armor)
public_key.verify_bindings()
print(public_key.user_ids)

secret_key, _ = SecretKey.from_armor(secret_key_armor)
assert secret_key.to_public_key().fingerprint == public_key.fingerprint

signed_message = sign_message(b"hello world", secret_key)
message, _ = Message.from_armor(signed_message)
message.verify(public_key)
assert message.payload_text() == "hello world"

signature = DetachedSignature.sign_binary(b"hello world", secret_key)
signature.verify(public_key, b"hello world")
```

## Current binding surface

- Parse ASCII-armored or binary transferable public keys.
- Parse ASCII-armored or binary transferable secret keys.
- Expose key metadata such as fingerprints, key IDs, subkey counts, and user IDs.
- Serialize keys back to binary packets or ASCII armor.
- Parse OpenPGP messages into reusable Python `Message` objects.
- Read signed/literal/compressed message payloads and inspect literal metadata.
- Verify signed messages against public keys.
- Parse, serialize, create, and verify detached signatures.
- Create simple signed OpenPGP messages with `sign_message(...)`.
- Verify key self-signatures and bindings.
- Convert a parsed secret key to its public-key view.
- Inspect whether OpenPGP message data is literal, compressed, signed, or encrypted.
