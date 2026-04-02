from collections.abc import Callable
from typing import Final, Literal

import pytest

from openpgp import (
    EncryptionCaps,
    KeyType,
    Message,
    PublicKey,
    SecretKey,
    SecretKeyParamsBuilder,
    SubkeyParamsBuilder,
    encrypt_message_to_recipient,
    sign_message,
)


SymmetricPreferenceName = Literal["aes128", "aes192", "aes256"]
HashPreferenceName = Literal[
    "sha1", "sha224", "sha256", "sha384", "sha512", "sha3-256", "sha3-512"
]
CompressionPreferenceName = Literal["zip", "zlib", "bzip2"]
KeyVersion = Literal[4, 6]

DEFAULT_SYMMETRIC_PREFERENCES: Final[list[SymmetricPreferenceName]] = [
    "aes256",
    "aes192",
    "aes128",
]
DEFAULT_HASH_PREFERENCES: Final[list[HashPreferenceName]] = [
    "sha256",
    "sha384",
    "sha512",
    "sha224",
]
DEFAULT_COMPRESSION_PREFERENCES: Final[list[CompressionPreferenceName]] = [
    "zlib",
    "zip",
]
AES256_ONLY: Final[list[SymmetricPreferenceName]] = ["aes256"]
SHA512_ONLY: Final[list[HashPreferenceName]] = ["sha512"]
ZLIB_ONLY: Final[list[CompressionPreferenceName]] = ["zlib"]


def build_modern_signing_key(version: KeyVersion) -> SecretKeyParamsBuilder:
    """Adapted from upstream builder.rs `key_gen_25519_rfc9580_short`."""

    return (
        SecretKeyParamsBuilder()
        .version(version)
        .key_type(KeyType.ed25519())
        .can_certify(True)
        .can_sign(True)
        .primary_user_id("Me-X <me-25519-rfc9580@mail.com>")
        .preferred_symmetric_algorithms(DEFAULT_SYMMETRIC_PREFERENCES)
        .preferred_hash_algorithms(DEFAULT_HASH_PREFERENCES)
        .preferred_compression_algorithms(DEFAULT_COMPRESSION_PREFERENCES)
    )


@pytest.mark.parametrize("version", [4, 6])
def test_generate_ed25519_x25519_key_roundtrips(version: KeyVersion) -> None:
    """Adapt upstream short key-generation coverage for RFC 9580 25519 keys."""

    secret_key = (
        build_modern_signing_key(version)
        .subkey(
            SubkeyParamsBuilder()
            .version(version)
            .key_type(KeyType.x25519())
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )

    public_key = secret_key.to_public_key()

    assert secret_key.secret_subkey_count == 1
    assert public_key.public_subkey_count == 1
    assert public_key.user_ids == ["Me-X <me-25519-rfc9580@mail.com>"]

    secret_key.verify_bindings()
    public_key.verify_bindings()

    reparsed_secret, headers = SecretKey.from_armor(secret_key.to_armored())
    assert headers == {}
    reparsed_secret.verify_bindings()
    assert reparsed_secret.fingerprint == secret_key.fingerprint

    reparsed_public, headers = PublicKey.from_armor(public_key.to_armored())
    assert headers == {}
    reparsed_public.verify_bindings()
    assert reparsed_public.fingerprint == public_key.fingerprint

    signed = sign_message(b"generated payload", reparsed_secret)
    signed_message, _ = Message.from_armor(signed)
    signed_message.verify(reparsed_public)
    assert signed_message.payload_bytes() == b"generated payload"

    encrypted = encrypt_message_to_recipient(b"hello world", reparsed_public)
    encrypted_message, _ = Message.from_armor(encrypted)
    decrypted = encrypted_message.decrypt(reparsed_secret)
    assert decrypted.payload_bytes() == b"hello world"


def test_generate_legacy_curve25519_key_matches_docs_example() -> None:
    """Adapt the docs.rs composed-module example for legacy Curve25519 generation."""

    secret_key = (
        SecretKeyParamsBuilder()
        .key_type(KeyType.ed25519_legacy())
        .can_certify(False)
        .can_sign(True)
        .primary_user_id("Me <me@example.com>")
        .preferred_symmetric_algorithms(["aes128"])
        .preferred_hash_algorithms(["sha256"])
        .preferred_compression_algorithms([])
        .subkey(
            SubkeyParamsBuilder()
            .key_type(KeyType.ecdh("curve25519"))
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )

    public_key = secret_key.to_public_key()

    secret_key.verify_bindings()
    public_key.verify_bindings()
    assert public_key.user_ids == ["Me <me@example.com>"]

    encrypted = encrypt_message_to_recipient(b"Hello World", public_key)
    encrypted_message, _ = Message.from_armor(encrypted)
    decrypted = encrypted_message.decrypt(secret_key)
    assert decrypted.payload_bytes() == b"Hello World"


@pytest.mark.parametrize("version", [4, 6])
def test_generate_ecdsa_p256_ecdh_p256_key_roundtrips(version: KeyVersion) -> None:
    """Adapt upstream `key_gen_ecdsa_p256_*` coverage into Python bindings."""

    secret_key = (
        SecretKeyParamsBuilder()
        .version(version)
        .key_type(KeyType.ecdsa("p256"))
        .can_certify(True)
        .can_sign(True)
        .primary_user_id("Me-X <me-ecdsa@mail.com>")
        .preferred_symmetric_algorithms(DEFAULT_SYMMETRIC_PREFERENCES)
        .preferred_hash_algorithms(DEFAULT_HASH_PREFERENCES)
        .preferred_compression_algorithms(DEFAULT_COMPRESSION_PREFERENCES)
        .subkey(
            SubkeyParamsBuilder()
            .version(version)
            .key_type(KeyType.ecdh("p256"))
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )

    public_key = secret_key.to_public_key()
    secret_key.verify_bindings()
    public_key.verify_bindings()
    assert public_key.user_ids == ["Me-X <me-ecdsa@mail.com>"]


def test_generate_passphrase_protected_key_requires_password_for_signing() -> None:
    """Adapt the encrypted-key generation flow from upstream builder tests."""

    protected_key = (
        build_modern_signing_key(6)
        .passphrase("hello")
        .subkey(
            SubkeyParamsBuilder()
            .version(6)
            .key_type(KeyType.x25519())
            .passphrase("hello")
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
        .build()
        .generate()
    )
    public_key = protected_key.to_public_key()

    reparsed_secret, _ = SecretKey.from_armor(protected_key.to_armored())

    with pytest.raises(ValueError):
        sign_message(b"payload", reparsed_secret)

    armored = sign_message(b"payload", reparsed_secret, password="hello")
    message, _ = Message.from_armor(armored)
    message.verify(public_key)
    assert message.payload_bytes() == b"payload"

    encrypted = encrypt_message_to_recipient(b"secret", public_key)
    encrypted_message, _ = Message.from_armor(encrypted)
    assert encrypted_message.decrypt(reparsed_secret, "hello").payload_bytes() == b"secret"


@pytest.mark.parametrize(
    ("builder", "match"),
    [
        (
            lambda: (
                SecretKeyParamsBuilder()
                .version(4)
                .key_type(KeyType.ed25519())
                .can_certify(True)
                .can_sign(True)
                .preferred_symmetric_algorithms(AES256_ONLY)
                .preferred_hash_algorithms(SHA512_ONLY)
                .preferred_compression_algorithms(ZLIB_ONLY)
                .subkey(
                    SubkeyParamsBuilder()
                    .version(4)
                    .key_type(KeyType.x25519())
                    .can_encrypt(EncryptionCaps.all())
                    .build()
                )
            ),
            "V4 keys must have a primary User ID",
        ),
        (
            lambda: (
                SecretKeyParamsBuilder()
                .version(6)
                .key_type(KeyType.ed25519())
                .can_certify(True)
                .can_sign(True)
                .primary_user_id("alice")
                .preferred_symmetric_algorithms(AES256_ONLY)
                .preferred_hash_algorithms(SHA512_ONLY)
                .preferred_compression_algorithms(ZLIB_ONLY)
                .subkey(
                    SubkeyParamsBuilder()
                    .version(4)
                    .key_type(KeyType.x25519())
                    .can_encrypt(EncryptionCaps.all())
                    .build()
                )
            ),
            "V6 primary key may not be combined with V4 subkey",
        ),
        (
            lambda: (
                SecretKeyParamsBuilder()
                .version(4)
                .key_type(KeyType.ed25519())
                .can_certify(True)
                .can_sign(True)
                .primary_user_id("alice")
                .preferred_symmetric_algorithms(AES256_ONLY)
                .preferred_hash_algorithms(SHA512_ONLY)
                .preferred_compression_algorithms(ZLIB_ONLY)
                .subkey(
                    SubkeyParamsBuilder()
                    .version(6)
                    .key_type(KeyType.x25519())
                    .can_encrypt(EncryptionCaps.all())
                    .build()
                )
            ),
            "primary key may not be combined with V6 subkey",
        ),
    ],
)
def test_builder_validation_errors_are_exposed_to_python(
    builder: Callable[[], SecretKeyParamsBuilder],
    match: str,
) -> None:
    """Adapt upstream builder validation failures into Python exceptions."""

    with pytest.raises(ValueError, match=match):
        builder().build()


@pytest.mark.parametrize(
    ("builder", "match"),
    [
        (
            lambda: SecretKeyParamsBuilder()
            .version(6)
            .key_type(KeyType.ed25519())
            .can_certify(True)
            .can_sign(True)
            .primary_user_id("alice")
            .subkey(
                SubkeyParamsBuilder()
                .version(6)
                .key_type(KeyType.x25519())
                .can_sign(True)
                .build()
            ),
            "can not be used for signing keys",
        ),
        (
            lambda: SecretKeyParamsBuilder()
            .version(6)
            .key_type(KeyType.ed25519())
            .can_certify(True)
            .can_sign(True)
            .primary_user_id("alice")
            .subkey(
                SubkeyParamsBuilder()
                .version(6)
                .key_type(KeyType.ed25519())
                .can_encrypt(EncryptionCaps.all())
                .build()
            ),
            "can not be used for encryption keys",
        ),
    ],
)
def test_key_type_validation_errors_are_exposed_to_python(
    builder: Callable[[], SecretKeyParamsBuilder],
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        builder().build()


def test_key_type_capability_helpers_match_upstream_semantics() -> None:
    assert KeyType.ed25519().can_sign() is True
    assert KeyType.ed25519().can_encrypt() is False
    assert KeyType.x25519().can_sign() is False
    assert KeyType.x25519().can_encrypt() is True
    assert KeyType.rsa(2048).can_sign() is True
    assert KeyType.rsa(2048).can_encrypt() is True


def test_signing_capable_subkey_generation_verifies_bindings() -> None:
    """Adapt upstream `signing_capable_subkey` coverage with Python-visible assertions."""

    secret_key = (
        SecretKeyParamsBuilder()
        .version(6)
        .key_type(KeyType.ed25519())
        .can_certify(True)
        .primary_user_id("alice")
        .subkey(
            SubkeyParamsBuilder()
            .version(6)
            .key_type(KeyType.ed25519())
            .can_sign(True)
            .build()
        )
        .build()
        .generate()
    )

    public_key = secret_key.to_public_key()

    assert secret_key.secret_subkey_count == 1
    assert public_key.public_subkey_count == 1
    secret_key.verify_bindings()
    public_key.verify_bindings()
