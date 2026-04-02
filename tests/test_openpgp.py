from pathlib import Path

import pytest

from openpgp import (
    CleartextSignedMessage,
    DetachedSignature,
    Message,
    PublicKey,
    SecretKey,
    encrypt_message_to_recipient,
    encrypt_message_with_password,
    inspect_message,
    sign_cleartext_message,
    sign_message,
)


PUBLIC_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----"""

SECRET_KEY = """-----BEGIN PGP PRIVATE KEY BLOCK-----

xUsGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laMAGXKB
exK+cH6NX1hs5hNhIB00TrJmosgv3mg1ditlsLfCsQYfGwoAAABCBYJjh3/jAwsJ
BwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lwgyU2kCcUmKfvBXbAf6rh
RYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaEQsiPlR4zxP/TP7mhfVEe
7XWPxtnMUMtf15OyA51YBMdLBmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/
LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u/tVY6a//1q0NWC1X+yui3O24wpsG
GBsKAAAALAWCY4d/4wKbDCIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAAQBIKbpGG2dWTX8j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDE
M0g12vYxoWM8Y81W+bHBw805I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUr
k0mXubZvyl4GBg==
-----END PGP PRIVATE KEY BLOCK-----"""


def test_parse_public_key_from_armor() -> None:
    key, headers = PublicKey.from_armor(PUBLIC_KEY)

    assert headers == {}
    assert key.fingerprint
    assert key.key_id
    assert key.public_subkey_count == 1
    assert key.user_ids == []
    assert PublicKey.from_bytes(key.to_bytes()).fingerprint == key.fingerprint
    key.verify_bindings()


def test_parse_secret_key_and_convert_to_public() -> None:
    secret_key, headers = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    assert headers == {}
    assert secret_key.secret_subkey_count == 1
    assert public_key.public_subkey_count == 1
    assert public_key.fingerprint == secret_key.fingerprint
    assert secret_key.user_ids == public_key.user_ids
    secret_key.verify_bindings()


def test_round_trip_public_key_armor() -> None:
    key, _ = PublicKey.from_armor(PUBLIC_KEY)
    reparsed, headers = PublicKey.from_armor(key.to_armored())

    assert headers == {}
    assert reparsed.fingerprint == key.fingerprint


def test_sign_and_verify_message() -> None:
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    armored = sign_message(b"Hello world", secret_key)
    message, headers = Message.from_armor(armored)

    assert headers == {}
    assert message.kind == "signed"
    assert message.is_signed is True
    assert message.is_literal is False
    assert message.literal_mode() == "binary"
    assert message.literal_filename() == b""
    assert message.payload_bytes() == b"Hello world"
    assert message.payload_text() == "Hello world"
    message.verify(public_key)


def test_sign_and_verify_detached_signature() -> None:
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()
    payload = b"detached payload"

    signature = DetachedSignature.sign_binary(payload, secret_key)
    signature.verify(public_key, payload)

    reparsed = DetachedSignature.from_bytes(signature.to_bytes())
    reparsed.verify(public_key, payload)

    armored_signature, headers = DetachedSignature.from_armor(signature.to_armored())
    assert headers == {}
    armored_signature.verify(public_key, payload)


def test_encrypt_and_decrypt_message_with_password_seipdv1() -> None:
    armored = encrypt_message_with_password(
        b"secret payload",
        "hunter2",
        file_name="note.txt",
        version="seipd-v1",
    )
    message, headers = Message.from_armor(armored)

    assert headers == {}
    assert inspect_message(armored).kind == "encrypted"
    assert message.kind == "encrypted"
    with pytest.raises(ValueError, match="message must be decrypted"):
        message.payload_text()

    decrypted = message.decrypt_with_password("hunter2")

    assert decrypted.kind == "literal"
    assert decrypted.literal_filename() == b""
    assert decrypted.payload_text() == "secret payload"


def test_encrypt_and_decrypt_message_with_password_seipdv2_and_compression() -> None:
    armored = encrypt_message_with_password(
        b"compressed payload",
        "opensesame",
        version="seipd-v2",
        compression="zlib",
    )
    message, _ = Message.from_armor(armored)
    decrypted = message.decrypt_with_password("opensesame")

    assert decrypted.kind == "compressed"
    assert decrypted.is_compressed is True
    assert decrypted.literal_mode() == "binary"
    assert decrypted.payload_text() == "compressed payload"


def test_encrypt_and_decrypt_message_to_recipient() -> None:
    secret_key, _ = SecretKey.from_armor(SECRET_KEY)
    public_key = secret_key.to_public_key()

    armored = encrypt_message_to_recipient(
        b"recipient payload",
        public_key,
        file_name="message.bin",
    )
    message, headers = Message.from_armor(armored)
    decrypted = message.decrypt(secret_key)

    assert headers == {}
    assert message.kind == "encrypted"
    assert decrypted.literal_filename() == b""
    assert decrypted.payload_bytes() == b"recipient payload"


def test_cleartext_sign_and_verify_round_trip() -> None:
    fixture = Path(__file__).resolve().parent / "fixtures" / "cleartext-key-01.asc"
    secret_key, _ = SecretKey.from_armor(fixture.read_text())
    public_key = secret_key.to_public_key()
    text = "hello\n-world-what-\nis up\n"

    armored = sign_cleartext_message(text, secret_key)
    message, headers = CleartextSignedMessage.from_armor(armored)

    assert headers == {}
    assert "-----BEGIN PGP SIGNED MESSAGE-----" in armored
    assert "Hash: SHA256" in armored
    assert "- -world-what-" in message.text
    assert message.signed_text() == "hello\r\n-world-what-\r\nis up\r\n"
    message.verify(public_key)

    reparsed, round_trip_headers = CleartextSignedMessage.from_armor(
        message.to_armored()
    )
    assert round_trip_headers == {}
    assert reparsed.signed_text() == message.signed_text()
