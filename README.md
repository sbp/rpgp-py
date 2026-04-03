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

## Examples

### Parse, sign, encrypt, and inspect OpenPGP data

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
```

### Generate RFC 9580-compatible key material with builder APIs

```python
from openpgp import (
    EncryptionCaps,
    KeyType,
    Message,
    PacketHeaderVersion,
    SecretKeyParamsBuilder,
    SubkeyParamsBuilder,
    UserAttribute,
    encrypt_message_to_recipient,
    sign_message,
)

secret_key = (
    SecretKeyParamsBuilder()
    .version(6)
    .key_type(KeyType.ed25519())
    .can_certify(True)
    .can_sign(True)
    .packet_version(PacketHeaderVersion.new())
    .feature_seipd_v2(True)
    .primary_user_id("Me <me@example.com>")
    .preferred_symmetric_algorithms(["aes256", "aes192", "aes128"])
    .preferred_hash_algorithms(["sha256", "sha384", "sha512", "sha224"])
    .preferred_compression_algorithms(["zlib", "zip"])
    .user_attribute(UserAttribute.image_jpeg(bytes.fromhex("ffd8ffe000104a464946000101")))
    .subkey(
        SubkeyParamsBuilder()
        .version(6)
        .key_type(KeyType.x25519())
        .packet_version(PacketHeaderVersion.new())
        .can_encrypt(EncryptionCaps.all())
        .build()
    )
    .build()
    .generate()
)

public_key = secret_key.to_public_key()
secret_key.verify_bindings()
public_key.verify_bindings()

direct_self_signature = public_key.direct_signature_infos()[0]
assert direct_self_signature.signature_type == "direct-key"
assert direct_self_signature.key_flags.certify is True
assert direct_self_signature.key_flags.sign is True
assert direct_self_signature.features is not None
assert direct_self_signature.features.seipd_v2 is True
assert direct_self_signature.preferred_hash_algorithms == ["sha256", "sha384", "sha512", "sha224"]

user_binding = public_key.user_bindings()[0]
assert user_binding.user_id == "Me <me@example.com>"
assert user_binding.is_primary is True
assert user_binding.signatures[0].signature_type == "cert-positive"

portrait_binding = public_key.user_attribute_bindings()[0]
assert portrait_binding.user_attribute.kind == "image"
assert portrait_binding.user_attribute.image_format == "jpeg"
assert portrait_binding.user_attribute.data == bytes.fromhex("ffd8ffe000104a464946000101")
assert portrait_binding.signatures[0].signature_type == "cert-positive"

signed = sign_message(b"generated payload", secret_key)
message, _ = Message.from_armor(signed)
message.verify(public_key)
assert message.payload_bytes() == b"generated payload"

encrypted = encrypt_message_to_recipient(b"secret", public_key)
encrypted_message, _ = Message.from_armor(encrypted)
assert encrypted_message.decrypt(secret_key).payload_bytes() == b"secret"
```

Use `PacketHeaderVersion.old()` when you need legacy packet-header framing for the serialized
primary-key or subkey packets, for example when round-tripping older transferable key material.

### Customize secret-key S2K protection for generated keys

```python
from openpgp import (
    EncryptionCaps,
    KeyType,
    S2kParams,
    SecretKeyParamsBuilder,
    StringToKey,
    SubkeyParamsBuilder,
)

secret_key = (
    SecretKeyParamsBuilder()
    .version(6)
    .key_type(KeyType.ed25519())
    .can_certify(True)
    .can_sign(True)
    .primary_user_id("Me <me@example.com>")
    .passphrase("hunter2")
    .s2k(
        S2kParams.aead(
            "aes256",
            "ocb",
            StringToKey.argon2(3, 4, 16),
        )
    )
    .subkey(
        SubkeyParamsBuilder()
        .version(6)
        .key_type(KeyType.x25519())
        .can_encrypt(EncryptionCaps.all())
        .passphrase("hunter2")
        .s2k(
            S2kParams.cfb(
                "aes128",
                StringToKey.iterated("sha256", 96),
            )
        )
        .build()
    )
    .build()
    .generate()
)

primary_s2k = secret_key.primary_secret_s2k()
assert primary_s2k.usage == "aead"
assert primary_s2k.aead_algorithm == "ocb"
assert primary_s2k.string_to_key is not None
assert primary_s2k.string_to_key.kind == "argon2"

subkey_s2k = secret_key.secret_subkey_s2ks()[0]
assert subkey_s2k.usage == "cfb"
assert subkey_s2k.string_to_key is not None
assert subkey_s2k.string_to_key.kind == "iterated-salted"
```

## Current binding surface

- Parse ASCII-armored or binary transferable public keys.
- Parse ASCII-armored or binary transferable secret keys.
- Expose key metadata such as fingerprints, key IDs, subkey counts, user IDs, and secret-key S2K protection settings.
- Inspect certificate self-signature metadata, including direct-key signatures, user-ID binding signatures, key flags, features, and preferred algorithm lists.
- Serialize keys back to binary packets or ASCII armor.
- Generate new transferable secret/public keys with typed builder APIs based on rPGP's `SecretKeyParamsBuilder` and `SubkeyParamsBuilder`.
- Configure key-generation parameters such as key versions, key flags, packet-header framing, user IDs, user attributes, preferred algorithms, SEIPD feature flags, passphrase protection, explicit S2K protection parameters, and subkeys.
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
