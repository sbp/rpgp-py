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
    SignatureInfo,
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



def build_certificate_metadata_key(
    version: KeyVersion,
    *,
    primary_user_id: str | None,
    feature_seipd_v1: bool = True,
    feature_seipd_v2: bool = False,
) -> SecretKey:
    """Adapt upstream certificate-metadata builder coverage into reusable helpers."""

    builder = (
        SecretKeyParamsBuilder()
        .version(version)
        .key_type(KeyType.ed25519())
        .can_certify(True)
        .can_sign(True)
        .feature_seipd_v1(feature_seipd_v1)
        .feature_seipd_v2(feature_seipd_v2)
        .preferred_symmetric_algorithms(AES256_ONLY)
        .preferred_hash_algorithms(SHA512_ONLY)
        .preferred_compression_algorithms(ZLIB_ONLY)
        .subkey(
            SubkeyParamsBuilder()
            .version(version)
            .key_type(KeyType.x25519())
            .can_encrypt(EncryptionCaps.all())
            .build()
        )
    )
    if primary_user_id is not None:
        builder = builder.primary_user_id(primary_user_id)
    return builder.build().generate()


def assert_certificate_preferences_are_exposed_on_signature(
    info: SignatureInfo,
    *,
    has_features: bool,
    seipd_v1: bool,
    seipd_v2: bool,
) -> None:
    """Assert the self-signature metadata surfaced from upstream certificate builders."""

    assert info.preferred_symmetric_algorithms == ["aes256"]
    assert info.preferred_hash_algorithms == ["sha512"]
    assert info.preferred_compression_algorithms == ["zlib"]
    assert info.preferred_aead_algorithms == []
    assert info.key_flags.certify is True
    assert info.key_flags.sign is True
    assert info.key_flags.encrypt_communications is False
    assert info.key_flags.encrypt_storage is False
    assert info.key_flags.authenticate is False

    if has_features:
        assert info.features is not None
        assert info.features.seipd_v1 is seipd_v1
        assert info.features.seipd_v2 is seipd_v2
    else:
        assert info.features is None


def test_v4_certificate_metadata_is_exposed_on_primary_user_binding_signature() -> None:
    """Adapt upstream `test_cert_metadata_gen_v4_v4` into Python-visible metadata access."""

    secret_key = build_certificate_metadata_key(4, primary_user_id="alice")
    public_key = secret_key.to_public_key()

    assert secret_key.direct_signature_infos() == []
    assert public_key.direct_signature_infos() == []

    secret_bindings = secret_key.user_bindings()
    public_bindings = public_key.user_bindings()
    assert len(secret_bindings) == 1
    assert len(public_bindings) == 1

    secret_binding = secret_bindings[0]
    public_binding = public_bindings[0]
    assert secret_binding.user_id == "alice"
    assert secret_binding.is_primary is True
    assert len(secret_binding.signatures) == 1
    assert public_binding.user_id == "alice"
    assert public_binding.is_primary is True
    assert len(public_binding.signatures) == 1

    secret_info = secret_binding.signatures[0]
    public_info = public_binding.signatures[0]
    assert secret_info.signature_type == "cert-positive"
    assert public_info.signature_type == "cert-positive"
    assert_certificate_preferences_are_exposed_on_signature(
        secret_info,
        has_features=True,
        seipd_v1=True,
        seipd_v2=False,
    )
    assert_certificate_preferences_are_exposed_on_signature(
        public_info,
        has_features=True,
        seipd_v1=True,
        seipd_v2=False,
    )



def test_v6_certificate_metadata_moves_to_direct_key_signature() -> None:
    """Adapt upstream `test_cert_metadata_gen_v6_v6` into Python-visible metadata access."""

    secret_key = build_certificate_metadata_key(
        6,
        primary_user_id="alice",
        feature_seipd_v2=True,
    )
    public_key = secret_key.to_public_key()

    secret_direct_signatures = secret_key.direct_signature_infos()
    public_direct_signatures = public_key.direct_signature_infos()
    assert len(secret_direct_signatures) == 1
    assert len(public_direct_signatures) == 1

    secret_direct = secret_direct_signatures[0]
    public_direct = public_direct_signatures[0]
    assert secret_direct.signature_type == "direct-key"
    assert public_direct.signature_type == "direct-key"
    assert_certificate_preferences_are_exposed_on_signature(
        secret_direct,
        has_features=True,
        seipd_v1=True,
        seipd_v2=True,
    )
    assert_certificate_preferences_are_exposed_on_signature(
        public_direct,
        has_features=True,
        seipd_v1=True,
        seipd_v2=True,
    )

    secret_binding = secret_key.user_bindings()[0]
    public_binding = public_key.user_bindings()[0]
    secret_binding_info = secret_binding.signatures[0]
    public_binding_info = public_binding.signatures[0]
    assert secret_binding.user_id == "alice"
    assert secret_binding.is_primary is True
    assert public_binding.user_id == "alice"
    assert public_binding.is_primary is True
    assert secret_binding_info.preferred_symmetric_algorithms == []
    assert secret_binding_info.preferred_hash_algorithms == []
    assert secret_binding_info.preferred_compression_algorithms == []
    assert secret_binding_info.preferred_aead_algorithms == []
    assert public_binding_info.preferred_symmetric_algorithms == []
    assert public_binding_info.preferred_hash_algorithms == []
    assert public_binding_info.preferred_compression_algorithms == []
    assert public_binding_info.preferred_aead_algorithms == []
    assert secret_binding_info.key_flags.certify is False
    assert secret_binding_info.key_flags.sign is False
    assert public_binding_info.key_flags.certify is False
    assert public_binding_info.key_flags.sign is False
    assert secret_binding_info.features is None
    assert public_binding_info.features is None



def test_v6_id_less_certificate_still_exposes_direct_key_signature_metadata() -> None:
    """Adapt upstream `test_cert_metadata_gen_v6_v6_id_less` into Python-visible metadata access."""

    secret_key = build_certificate_metadata_key(
        6,
        primary_user_id=None,
        feature_seipd_v1=False,
        feature_seipd_v2=True,
    )
    public_key = secret_key.to_public_key()

    assert secret_key.user_bindings() == []
    assert public_key.user_bindings() == []

    secret_direct = secret_key.direct_signature_infos()
    public_direct = public_key.direct_signature_infos()
    assert len(secret_direct) == 1
    assert len(public_direct) == 1
    assert_certificate_preferences_are_exposed_on_signature(
        secret_direct[0],
        has_features=True,
        seipd_v1=False,
        seipd_v2=True,
    )
    assert_certificate_preferences_are_exposed_on_signature(
        public_direct[0],
        has_features=True,
        seipd_v1=False,
        seipd_v2=True,
    )
