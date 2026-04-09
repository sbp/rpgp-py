use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    sync::Mutex,
};

use pgp::{
    armor::Dearmor,
    composed::{
        ArmorOptions, CleartextSignedMessage as PgpCleartextSignedMessage, Deserializable,
        DetachedSignature as PgpDetachedSignature, DsaKeySize as PgpDsaKeySize,
        EncryptionCaps as PgpEncryptionCaps, FullSignaturePacket, KeyType as PgpKeyType,
        Message as PgpMessage, MessageBuilder, PlainSessionKey as PgpPlainSessionKey,
        RawSessionKey as PgpRawSessionKey, SecretKeyParams as PgpSecretKeyParams,
        SecretKeyParamsBuilder as PgpSecretKeyParamsBuilder, SignedPublicKey,
        SignedPublicSubKey, SignedSecretKey, SignedSecretSubKey,
        SubkeyParams as PgpSubkeyParams, SubkeyParamsBuilder as PgpSubkeyParamsBuilder,
    },
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        ecc_curve::ECCCurve,
        hash::HashAlgorithm,
        public_key::PublicKeyAlgorithm as PgpPublicKeyAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::{
        DataMode, Features as PgpFeatures, ImageHeader as PgpImageHeader,
        ImageHeaderV1 as PgpImageHeaderV1, KeyFlags as PgpKeyFlags, Packet as PgpPacket,
        PacketHeader, PacketParser, PacketTrait,
        PublicKeyEncryptedSessionKey as PgpPublicKeyEncryptedSessionKey, Signature,
        SignatureType, SignatureVersion, SignatureVersionSpecific,
        SymEncryptedProtectedDataConfig as PgpSymEncryptedProtectedDataConfig,
        SymKeyEncryptedSessionKey as PgpSymKeyEncryptedSessionKey,
        UserAttribute as PgpUserAttribute, UserAttributeType as PgpUserAttributeType,
    },
    ser::Serialize,
    types::{
        CompressionAlgorithm, EcdhPublicParams as PgpEcdhPublicParams,
        EcdsaPublicParams as PgpEcdsaPublicParams,
        EddsaLegacyPublicParams as PgpEddsaLegacyPublicParams, KeyDetails, KeyVersion,
        PacketHeaderVersion as PgpPacketHeaderVersion, PacketLength, Password,
        PublicParams as PgpPublicParams, S2kParams as PgpS2kParams,
        SecretParams as PgpSecretParams, StringToKey as PgpStringToKey, Tag, Timestamp,
    },
};
use pyo3::{
    basic::CompareOp,
    exceptions::PyValueError,
    prelude::*,
    types::{PyModule, PyModuleMethods},
};
use rand::Rng;
use smallvec::SmallVec;

type Headers = BTreeMap<String, Vec<String>>;

fn to_py_err(error: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(error.to_string())
}

fn parse_message(source: &[u8]) -> Result<(PgpMessage<'_>, Option<Headers>), pgp::errors::Error> {
    PgpMessage::from_reader(Cursor::new(source))
}

fn inspect_message_from_source(source: &[u8]) -> Result<MessageInfo, pgp::errors::Error> {
    let (message, headers) = parse_message(source)?;
    Ok(message_info_from_parts(message, headers))
}

fn message_info_from_ref(message: &PgpMessage<'_>, headers: Option<Headers>) -> MessageInfo {
    let (kind, is_nested) = match message {
        PgpMessage::Literal { is_nested, .. } => ("literal", *is_nested),
        PgpMessage::Compressed { is_nested, .. } => ("compressed", *is_nested),
        PgpMessage::Signed { is_nested, .. } => ("signed", *is_nested),
        PgpMessage::Encrypted { is_nested, .. } => ("encrypted", *is_nested),
    };

    MessageInfo {
        kind: kind.to_string(),
        is_nested,
        headers,
    }
}

fn message_info_from_parts(message: PgpMessage<'_>, headers: Option<Headers>) -> MessageInfo {
    message_info_from_ref(&message, headers)
}

fn parse_message_info_from_reader(
    reader: Cursor<&[u8]>,
) -> Result<MessageInfo, pgp::errors::Error> {
    let (message, headers) = PgpMessage::from_reader(reader)?;
    Ok(message_info_from_parts(message, headers))
}

fn prepare_message_for_content(source: &[u8]) -> Result<PgpMessage<'_>, pgp::errors::Error> {
    let (mut message, _) = parse_message(source)?;
    while message.is_compressed() {
        message = message.decompress()?;
    }
    Ok(message)
}

fn payload_bytes_from_source(source: &[u8]) -> PyResult<Vec<u8>> {
    let mut message = prepare_message_for_content(source).map_err(to_py_err)?;
    if matches!(message, PgpMessage::Encrypted { .. }) {
        return Err(to_py_err(
            "message must be decrypted before reading payload",
        ));
    }
    message.as_data_vec().map_err(to_py_err)
}

fn payload_text_from_source(source: &[u8]) -> PyResult<String> {
    let mut message = prepare_message_for_content(source).map_err(to_py_err)?;
    if matches!(message, PgpMessage::Encrypted { .. }) {
        return Err(to_py_err(
            "message must be decrypted before reading payload",
        ));
    }
    message.as_data_string().map_err(to_py_err)
}

fn literal_mode_from_source(source: &[u8]) -> PyResult<Option<String>> {
    let message = prepare_message_for_content(source).map_err(to_py_err)?;
    Ok(message
        .literal_data_header()
        .map(|header| data_mode_name(header.mode())))
}

fn literal_filename_from_source(source: &[u8]) -> PyResult<Option<Vec<u8>>> {
    let message = prepare_message_for_content(source).map_err(to_py_err)?;
    Ok(message
        .literal_data_header()
        .map(|header| header.file_name().to_vec()))
}

fn signature_count_from_source(source: &[u8]) -> PyResult<usize> {
    let message = prepare_message_for_content(source).map_err(to_py_err)?;
    match message {
        PgpMessage::Signed { reader, .. } => Ok(reader.num_signatures()),
        PgpMessage::Encrypted { .. } => Err(to_py_err(
            "message must be decrypted before inspecting signatures",
        )),
        _ => Ok(0),
    }
}

fn one_pass_signature_count_from_source(source: &[u8]) -> PyResult<usize> {
    let message = prepare_message_for_content(source).map_err(to_py_err)?;
    match message {
        PgpMessage::Signed { reader, .. } => Ok(reader.num_one_pass_signatures()),
        PgpMessage::Encrypted { .. } => Err(to_py_err(
            "message must be decrypted before inspecting signatures",
        )),
        _ => Ok(0),
    }
}

fn regular_signature_count_from_source(source: &[u8]) -> PyResult<usize> {
    let message = prepare_message_for_content(source).map_err(to_py_err)?;
    match message {
        PgpMessage::Signed { reader, .. } => Ok(reader.num_regular_signatures()),
        PgpMessage::Encrypted { .. } => Err(to_py_err(
            "message must be decrypted before inspecting signatures",
        )),
        _ => Ok(0),
    }
}

fn signature_infos_from_source(source: &[u8]) -> PyResult<Vec<SignatureInfo>> {
    let message = prepare_message_for_content(source).map_err(to_py_err)?;
    signature_infos_from_signed_message(message)
}

fn verify_signature_from_source(
    source: &[u8],
    key: &SignedPublicKey,
    index: usize,
) -> PyResult<SignatureInfo> {
    let message = prepare_message_for_content(source).map_err(to_py_err)?;
    verify_message_signature_info(message, key, index)
}

fn password_from_option(password: Option<&str>) -> Password {
    match password {
        Some(password) if !password.is_empty() => password.into(),
        _ => Password::empty(),
    }
}

fn key_version_from_number(version: u8) -> PyResult<KeyVersion> {
    match version {
        4 => Ok(KeyVersion::V4),
        6 => Ok(KeyVersion::V6),
        _ => Err(to_py_err("unsupported key version; expected 4 or 6")),
    }
}

fn timestamp_from_seconds(seconds: u32) -> Timestamp {
    Timestamp::from_secs(seconds)
}

fn key_version_number(version: KeyVersion) -> u8 {
    version.into()
}

fn public_key_algorithm_name(algorithm: PgpPublicKeyAlgorithm) -> &'static str {
    match algorithm {
        PgpPublicKeyAlgorithm::RSA => "rsa",
        PgpPublicKeyAlgorithm::RSAEncrypt => "rsa-encrypt",
        PgpPublicKeyAlgorithm::RSASign => "rsa-sign",
        PgpPublicKeyAlgorithm::ElgamalEncrypt => "elgamal-encrypt",
        PgpPublicKeyAlgorithm::DSA => "dsa",
        PgpPublicKeyAlgorithm::ECDH => "ecdh",
        PgpPublicKeyAlgorithm::ECDSA => "ecdsa",
        PgpPublicKeyAlgorithm::Elgamal => "elgamal",
        PgpPublicKeyAlgorithm::DiffieHellman => "diffie-hellman",
        PgpPublicKeyAlgorithm::EdDSALegacy => "eddsa-legacy",
        PgpPublicKeyAlgorithm::X25519 => "x25519",
        PgpPublicKeyAlgorithm::X448 => "x448",
        PgpPublicKeyAlgorithm::Ed25519 => "ed25519",
        PgpPublicKeyAlgorithm::Ed448 => "ed448",
        PgpPublicKeyAlgorithm::Private100 => "private-100",
        PgpPublicKeyAlgorithm::Private101 => "private-101",
        PgpPublicKeyAlgorithm::Private102 => "private-102",
        PgpPublicKeyAlgorithm::Private103 => "private-103",
        PgpPublicKeyAlgorithm::Private104 => "private-104",
        PgpPublicKeyAlgorithm::Private105 => "private-105",
        PgpPublicKeyAlgorithm::Private106 => "private-106",
        PgpPublicKeyAlgorithm::Private107 => "private-107",
        PgpPublicKeyAlgorithm::Private108 => "private-108",
        PgpPublicKeyAlgorithm::Private109 => "private-109",
        PgpPublicKeyAlgorithm::Private110 => "private-110",
        PgpPublicKeyAlgorithm::Unknown(_) => "unknown",
        _ => "unknown",
    }
}

fn public_params_kind_name(params: &PgpPublicParams) -> &'static str {
    match params {
        PgpPublicParams::RSA(_) => "rsa",
        PgpPublicParams::DSA(_) => "dsa",
        PgpPublicParams::ECDSA(_) => "ecdsa",
        PgpPublicParams::ECDH(_) => "ecdh",
        PgpPublicParams::Elgamal(_) => "elgamal",
        PgpPublicParams::EdDSALegacy(_) => "eddsa-legacy",
        PgpPublicParams::Ed25519(_) => "ed25519",
        PgpPublicParams::X25519(_) => "x25519",
        PgpPublicParams::X448(_) => "x448",
        PgpPublicParams::Ed448(_) => "ed448",
        PgpPublicParams::Unknown { .. } => "unknown",
    }
}

fn curve_name_from_ecc_curve(curve: &ECCCurve) -> Option<&'static str> {
    match curve {
        ECCCurve::Curve25519 => Some("curve25519"),
        ECCCurve::Ed25519 => Some("ed25519"),
        ECCCurve::P256 => Some("p256"),
        ECCCurve::P384 => Some("p384"),
        ECCCurve::P521 => Some("p521"),
        ECCCurve::BrainpoolP256r1 => Some("brainpoolp256r1"),
        ECCCurve::BrainpoolP384r1 => Some("brainpoolp384r1"),
        ECCCurve::BrainpoolP512r1 => Some("brainpoolp512r1"),
        ECCCurve::Secp256k1 => Some("secp256k1"),
        ECCCurve::Unknown(_) => None,
    }
}

fn curve_bit_length_from_ecc_curve(curve: &ECCCurve) -> Option<u16> {
    match curve {
        ECCCurve::Curve25519
        | ECCCurve::Ed25519
        | ECCCurve::P256
        | ECCCurve::BrainpoolP256r1
        | ECCCurve::Secp256k1 => Some(256),
        ECCCurve::P384 | ECCCurve::BrainpoolP384r1 => Some(384),
        ECCCurve::P521 => Some(521),
        ECCCurve::BrainpoolP512r1 => Some(512),
        ECCCurve::Unknown(_) => None,
    }
}

fn curve_secret_key_length_from_ecc_curve(curve: &ECCCurve) -> Option<usize> {
    match curve {
        ECCCurve::Curve25519
        | ECCCurve::Ed25519
        | ECCCurve::P256
        | ECCCurve::BrainpoolP256r1
        | ECCCurve::Secp256k1 => Some(32),
        ECCCurve::P384 | ECCCurve::BrainpoolP384r1 => Some(48),
        ECCCurve::P521 => Some(66),
        ECCCurve::BrainpoolP512r1 => Some(64),
        ECCCurve::Unknown(_) => None,
    }
}

fn empty_public_params_info(kind: &str) -> PublicParamsInfo {
    PublicParamsInfo {
        kind: kind.to_string(),
        curve: None,
        curve_oid: None,
        curve_alias: None,
        curve_bits: None,
        secret_key_length: None,
        is_supported: None,
        kdf_hash_algorithm: None,
        kdf_symmetric_algorithm: None,
        kdf_type: None,
    }
}

fn set_curve_metadata(info: &mut PublicParamsInfo, curve: &ECCCurve) {
    info.curve = curve_name_from_ecc_curve(curve).map(str::to_string);
    info.curve_oid = Some(curve.oid_str());
    info.curve_alias = curve.alias().map(str::to_string);
    info.curve_bits = curve_bit_length_from_ecc_curve(curve);
    info.secret_key_length = curve_secret_key_length_from_ecc_curve(curve);
}

fn public_params_info_from_params(params: &PgpPublicParams) -> PublicParamsInfo {
    let kind = public_params_kind_name(params);
    let mut info = empty_public_params_info(kind);

    match params {
        PgpPublicParams::ECDSA(params) => match params {
            PgpEcdsaPublicParams::P256 { .. } => {
                set_curve_metadata(&mut info, &ECCCurve::P256);
                info.is_supported = Some(true);
            }
            PgpEcdsaPublicParams::P384 { .. } => {
                set_curve_metadata(&mut info, &ECCCurve::P384);
                info.is_supported = Some(true);
            }
            PgpEcdsaPublicParams::P521 { .. } => {
                set_curve_metadata(&mut info, &ECCCurve::P521);
                info.is_supported = Some(true);
            }
            PgpEcdsaPublicParams::Secp256k1 { .. } => {
                set_curve_metadata(&mut info, &ECCCurve::Secp256k1);
                info.is_supported = Some(true);
            }
            PgpEcdsaPublicParams::Unsupported { curve, .. } => {
                set_curve_metadata(&mut info, curve);
                info.is_supported = Some(false);
            }
        },
        PgpPublicParams::ECDH(params) => match params {
            PgpEcdhPublicParams::Curve25519 {
                hash,
                alg_sym,
                ecdh_kdf_type,
                ..
            } => {
                set_curve_metadata(&mut info, &ECCCurve::Curve25519);
                info.is_supported = Some(true);
                info.kdf_hash_algorithm = Some(normalized_algorithm_name(hash));
                info.kdf_symmetric_algorithm = Some(normalized_algorithm_name(alg_sym));
                info.kdf_type = Some(normalized_algorithm_name(ecdh_kdf_type));
            }
            PgpEcdhPublicParams::P256 { hash, alg_sym, .. } => {
                set_curve_metadata(&mut info, &ECCCurve::P256);
                info.is_supported = Some(true);
                info.kdf_hash_algorithm = Some(normalized_algorithm_name(hash));
                info.kdf_symmetric_algorithm = Some(normalized_algorithm_name(alg_sym));
            }
            PgpEcdhPublicParams::P384 { hash, alg_sym, .. } => {
                set_curve_metadata(&mut info, &ECCCurve::P384);
                info.is_supported = Some(true);
                info.kdf_hash_algorithm = Some(normalized_algorithm_name(hash));
                info.kdf_symmetric_algorithm = Some(normalized_algorithm_name(alg_sym));
            }
            PgpEcdhPublicParams::P521 { hash, alg_sym, .. } => {
                set_curve_metadata(&mut info, &ECCCurve::P521);
                info.is_supported = Some(true);
                info.kdf_hash_algorithm = Some(normalized_algorithm_name(hash));
                info.kdf_symmetric_algorithm = Some(normalized_algorithm_name(alg_sym));
            }
            PgpEcdhPublicParams::Brainpool256 { hash, alg_sym, .. } => {
                set_curve_metadata(&mut info, &ECCCurve::BrainpoolP256r1);
                info.is_supported = Some(true);
                info.kdf_hash_algorithm = Some(normalized_algorithm_name(hash));
                info.kdf_symmetric_algorithm = Some(normalized_algorithm_name(alg_sym));
            }
            PgpEcdhPublicParams::Brainpool384 { hash, alg_sym, .. } => {
                set_curve_metadata(&mut info, &ECCCurve::BrainpoolP384r1);
                info.is_supported = Some(true);
                info.kdf_hash_algorithm = Some(normalized_algorithm_name(hash));
                info.kdf_symmetric_algorithm = Some(normalized_algorithm_name(alg_sym));
            }
            PgpEcdhPublicParams::Brainpool512 { hash, alg_sym, .. } => {
                set_curve_metadata(&mut info, &ECCCurve::BrainpoolP512r1);
                info.is_supported = Some(true);
                info.kdf_hash_algorithm = Some(normalized_algorithm_name(hash));
                info.kdf_symmetric_algorithm = Some(normalized_algorithm_name(alg_sym));
            }
            PgpEcdhPublicParams::Unsupported { curve, .. } => {
                set_curve_metadata(&mut info, curve);
                info.is_supported = Some(false);
            }
        },
        PgpPublicParams::EdDSALegacy(params) => match params {
            PgpEddsaLegacyPublicParams::Ed25519 { .. } => {
                set_curve_metadata(&mut info, &ECCCurve::Ed25519);
                info.is_supported = Some(true);
            }
            PgpEddsaLegacyPublicParams::Unsupported { curve, .. } => {
                set_curve_metadata(&mut info, curve);
                info.is_supported = Some(false);
            }
        },
        PgpPublicParams::Ed25519(_) => {
            set_curve_metadata(&mut info, &ECCCurve::Ed25519);
            info.is_supported = Some(true);
        }
        PgpPublicParams::X25519(_) => {
            set_curve_metadata(&mut info, &ECCCurve::Curve25519);
            info.is_supported = Some(true);
        }
        _ => {}
    }

    info
}

fn hash_algorithm_from_name(name: &str) -> PyResult<HashAlgorithm> {
    match name.to_ascii_lowercase().as_str() {
        "sha1" => Ok(HashAlgorithm::Sha1),
        "sha224" => Ok(HashAlgorithm::Sha224),
        "sha256" => Ok(HashAlgorithm::Sha256),
        "sha384" => Ok(HashAlgorithm::Sha384),
        "sha512" => Ok(HashAlgorithm::Sha512),
        "sha3-256" | "sha3_256" => Ok(HashAlgorithm::Sha3_256),
        "sha3-512" | "sha3_512" => Ok(HashAlgorithm::Sha3_512),
        _ => Err(to_py_err(
            "unsupported hash algorithm; expected 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3-256', or 'sha3-512'",
        )),
    }
}

fn required_compression_algorithm_from_name(name: &str) -> PyResult<CompressionAlgorithm> {
    compression_algorithm_from_name(Some(name))?
        .ok_or_else(|| to_py_err("compression algorithm is required"))
}

fn curve_from_name(name: &str) -> PyResult<ECCCurve> {
    match name.to_ascii_lowercase().as_str() {
        "curve25519" => Ok(ECCCurve::Curve25519),
        "ed25519" => Ok(ECCCurve::Ed25519),
        "p256" => Ok(ECCCurve::P256),
        "p384" => Ok(ECCCurve::P384),
        "p521" => Ok(ECCCurve::P521),
        "brainpoolp256r1" => Ok(ECCCurve::BrainpoolP256r1),
        "brainpoolp384r1" => Ok(ECCCurve::BrainpoolP384r1),
        "brainpoolp512r1" => Ok(ECCCurve::BrainpoolP512r1),
        "secp256k1" => Ok(ECCCurve::Secp256k1),
        _ => Err(to_py_err(
            "unsupported elliptic-curve name; expected 'curve25519', 'p256', 'p384', 'p521', 'brainpoolp256r1', 'brainpoolp384r1', 'brainpoolp512r1', or 'secp256k1'",
        )),
    }
}

fn dsa_key_size_from_bits(bits: u32) -> PyResult<PgpDsaKeySize> {
    match bits {
        1024 => Ok(PgpDsaKeySize::B1024),
        2048 => Ok(PgpDsaKeySize::B2048),
        3072 => Ok(PgpDsaKeySize::B3072),
        _ => Err(to_py_err(
            "unsupported DSA key size; expected 1024, 2048, or 3072 bits",
        )),
    }
}

fn symmetric_algorithms_from_names(
    values: Vec<String>,
) -> PyResult<SmallVec<[SymmetricKeyAlgorithm; 8]>> {
    let mut algorithms = SmallVec::new();
    for value in values {
        algorithms.push(symmetric_algorithm_from_name(&value)?);
    }
    Ok(algorithms)
}

fn hash_algorithms_from_names(values: Vec<String>) -> PyResult<SmallVec<[HashAlgorithm; 8]>> {
    let mut algorithms = SmallVec::new();
    for value in values {
        algorithms.push(hash_algorithm_from_name(&value)?);
    }
    Ok(algorithms)
}

fn compression_algorithms_from_names(
    values: Vec<String>,
) -> PyResult<SmallVec<[CompressionAlgorithm; 8]>> {
    let mut algorithms = SmallVec::new();
    for value in values {
        algorithms.push(required_compression_algorithm_from_name(&value)?);
    }
    Ok(algorithms)
}

fn aead_algorithm_preferences_from_names(
    values: Vec<(String, String)>,
) -> PyResult<SmallVec<[(SymmetricKeyAlgorithm, AeadAlgorithm); 4]>> {
    let mut algorithms = SmallVec::new();
    for (symmetric_algorithm, aead_algorithm) in values {
        algorithms.push((
            symmetric_algorithm_from_name(&symmetric_algorithm)?,
            aead_algorithm_from_name(&aead_algorithm)?,
        ));
    }
    Ok(algorithms)
}

fn curve_name(curve: &ECCCurve) -> &'static str {
    match curve {
        ECCCurve::Curve25519 => "curve25519",
        ECCCurve::Ed25519 => "ed25519",
        ECCCurve::P256 => "p256",
        ECCCurve::P384 => "p384",
        ECCCurve::P521 => "p521",
        ECCCurve::BrainpoolP256r1 => "brainpoolp256r1",
        ECCCurve::BrainpoolP384r1 => "brainpoolp384r1",
        ECCCurve::BrainpoolP512r1 => "brainpoolp512r1",
        ECCCurve::Secp256k1 => "secp256k1",
        ECCCurve::Unknown(_) => "unknown",
    }
}

fn key_type_name(key_type: &PgpKeyType) -> String {
    match key_type {
        PgpKeyType::Rsa(bits) => format!("rsa({bits})"),
        PgpKeyType::ECDH(curve) => format!("ecdh('{}')", curve_name(curve)),
        PgpKeyType::Ed25519Legacy => "ed25519_legacy".to_string(),
        PgpKeyType::ECDSA(curve) => format!("ecdsa('{}')", curve_name(curve)),
        PgpKeyType::Dsa(PgpDsaKeySize::B1024) => "dsa(1024)".to_string(),
        PgpKeyType::Dsa(PgpDsaKeySize::B2048) => "dsa(2048)".to_string(),
        PgpKeyType::Dsa(PgpDsaKeySize::B3072) => "dsa(3072)".to_string(),
        PgpKeyType::Ed25519 => "ed25519".to_string(),
        PgpKeyType::Ed448 => "ed448".to_string(),
        PgpKeyType::X25519 => "x25519".to_string(),
        PgpKeyType::X448 => "x448".to_string(),
    }
}

fn lossy_user_ids(details: &pgp::composed::SignedKeyDetails) -> Vec<String> {
    details
        .users
        .iter()
        .map(|user| String::from_utf8_lossy(user.id.id()).into_owned())
        .collect()
}

fn user_attribute_kind_name(attribute: &PgpUserAttribute) -> &'static str {
    match attribute.typ() {
        PgpUserAttributeType::Image => "image",
        PgpUserAttributeType::Unknown(_) => "unknown",
    }
}

fn user_attribute_data(attribute: &PgpUserAttribute) -> Vec<u8> {
    match attribute {
        PgpUserAttribute::Image { data, .. } | PgpUserAttribute::Unknown { data, .. } => {
            data.to_vec()
        }
    }
}

fn user_attribute_image_header_version(attribute: &PgpUserAttribute) -> Option<u8> {
    match attribute {
        PgpUserAttribute::Image {
            header: PgpImageHeader::V1(_),
            ..
        } => Some(1),
        PgpUserAttribute::Image {
            header: PgpImageHeader::Unknown { version, .. },
            ..
        } => Some(*version),
        PgpUserAttribute::Unknown { .. } => None,
    }
}

fn user_attribute_image_format(attribute: &PgpUserAttribute) -> Option<String> {
    match attribute {
        PgpUserAttribute::Image {
            header: PgpImageHeader::V1(PgpImageHeaderV1::Jpeg { .. }),
            ..
        } => Some("jpeg".to_string()),
        PgpUserAttribute::Image {
            header: PgpImageHeader::V1(PgpImageHeaderV1::Unknown { format, .. }),
            ..
        } => Some(format!("unknown({format:#x})")),
        PgpUserAttribute::Image {
            header: PgpImageHeader::Unknown { .. },
            ..
        }
        | PgpUserAttribute::Unknown { .. } => None,
    }
}

fn data_mode_name(mode: DataMode) -> String {
    match mode {
        DataMode::Binary => "binary",
        DataMode::Text => "text",
        DataMode::Utf8 => "utf8",
        DataMode::Mime => "mime",
        DataMode::Other(_) => "other",
    }
    .to_string()
}

fn normalized_algorithm_name(value: impl std::fmt::Debug) -> String {
    format!("{value:?}").to_ascii_lowercase().replace('_', "-")
}

fn symmetric_algorithm_names(values: &[SymmetricKeyAlgorithm]) -> Vec<String> {
    values
        .iter()
        .map(normalized_algorithm_name)
        .collect::<Vec<_>>()
}

fn hash_algorithm_names(values: &[HashAlgorithm]) -> Vec<String> {
    values
        .iter()
        .map(normalized_algorithm_name)
        .collect::<Vec<_>>()
}

fn compression_algorithm_names(values: &[CompressionAlgorithm]) -> Vec<String> {
    values
        .iter()
        .map(normalized_algorithm_name)
        .collect::<Vec<_>>()
}

fn aead_algorithm_preference_names(
    values: &[(SymmetricKeyAlgorithm, AeadAlgorithm)],
) -> Vec<(String, String)> {
    values
        .iter()
        .map(|(symmetric_algorithm, aead_algorithm)| {
            (
                normalized_algorithm_name(symmetric_algorithm),
                normalized_algorithm_name(aead_algorithm),
            )
        })
        .collect::<Vec<_>>()
}

fn packet_header_version_name(version: PgpPacketHeaderVersion) -> &'static str {
    match version {
        PgpPacketHeaderVersion::Old => "old",
        PgpPacketHeaderVersion::New => "new",
    }
}

fn string_to_key_kind_name(value: &PgpStringToKey) -> &'static str {
    match value {
        PgpStringToKey::Simple { .. } => "simple",
        PgpStringToKey::Salted { .. } => "salted",
        PgpStringToKey::Reserved { .. } => "reserved",
        PgpStringToKey::IteratedAndSalted { .. } => "iterated-salted",
        PgpStringToKey::Argon2 { .. } => "argon2",
        PgpStringToKey::Private { .. } => "private",
        PgpStringToKey::Other { .. } => "other",
    }
}

fn s2k_usage_name(value: &PgpS2kParams) -> &'static str {
    match value {
        PgpS2kParams::Unprotected => "unprotected",
        PgpS2kParams::LegacyCfb { .. } => "legacy-cfb",
        PgpS2kParams::Aead { .. } => "aead",
        PgpS2kParams::Cfb { .. } => "cfb",
        PgpS2kParams::MalleableCfb { .. } => "malleable-cfb",
    }
}

fn exact_or_random_array<const N: usize>(
    value: Option<&[u8]>,
    field_name: &str,
) -> PyResult<[u8; N]> {
    match value {
        Some(value) => value
            .try_into()
            .map_err(|_| to_py_err(format!("{field_name} must be exactly {N} bytes"))),
        None => {
            let mut generated = [0u8; N];
            rand::thread_rng().fill(&mut generated[..]);
            Ok(generated)
        }
    }
}

fn exact_or_random_vec(
    value: Option<&[u8]>,
    expected_len: usize,
    field_name: &str,
) -> PyResult<Vec<u8>> {
    match value {
        Some(value) if value.len() == expected_len => Ok(value.to_vec()),
        Some(_) => Err(to_py_err(format!(
            "{field_name} must be exactly {expected_len} bytes"
        ))),
        None => {
            let mut generated = vec![0u8; expected_len];
            rand::thread_rng().fill(generated.as_mut_slice());
            Ok(generated)
        }
    }
}

fn packet_header_from_body_len(
    version: PgpPacketHeaderVersion,
    tag: Tag,
    body_len: usize,
) -> PyResult<PacketHeader> {
    let length = u32::try_from(body_len).map_err(to_py_err)?;
    PacketHeader::from_parts(version, tag, PacketLength::Fixed(length)).map_err(to_py_err)
}

fn serialize_packet_body<T: Serialize>(packet: &T) -> PyResult<Vec<u8>> {
    let mut body = Vec::new();
    packet.to_writer(&mut body).map_err(to_py_err)?;
    Ok(body)
}

fn serialize_packet_with_header<T: PacketTrait>(packet: &T) -> PyResult<Vec<u8>> {
    let mut bytes = Vec::new();
    packet.to_writer_with_header(&mut bytes).map_err(to_py_err)?;
    Ok(bytes)
}

fn binary_message_source(source: &[u8], headers: &Option<Headers>) -> PyResult<Vec<u8>> {
    if headers.is_some() {
        let mut bytes = Vec::new();
        let mut dearmor = Dearmor::new(Cursor::new(source));
        dearmor.read_to_end(&mut bytes).map_err(to_py_err)?;
        Ok(bytes)
    } else {
        Ok(source.to_vec())
    }
}

fn parse_top_level_packets(source: &[u8], headers: &Option<Headers>) -> PyResult<Vec<PgpPacket>> {
    let binary = binary_message_source(source, headers)?;
    PacketParser::new(Cursor::new(binary.as_slice()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(to_py_err)
}

fn raw_session_key_from_bytes(
    session_key: &[u8],
    symmetric_algorithm: SymmetricKeyAlgorithm,
) -> PyResult<PgpRawSessionKey> {
    let expected_len = symmetric_algorithm.key_size();
    if session_key.len() != expected_len {
        return Err(to_py_err(format!(
            "session_key must be exactly {expected_len} bytes for {symmetric_algorithm:?}"
        )));
    }
    Ok(session_key.to_vec().into())
}

fn reframe_secret_key_packet(
    packet: pgp::packet::SecretKey,
    version: PgpPacketHeaderVersion,
) -> PyResult<pgp::packet::SecretKey> {
    if packet.packet_header_version() == version {
        return Ok(packet);
    }

    let body = serialize_packet_body(&packet)?;
    let header = packet_header_from_body_len(version, Tag::SecretKey, body.len())?;
    pgp::packet::SecretKey::try_from_reader(header, Cursor::new(body.as_slice())).map_err(to_py_err)
}

fn reframe_secret_subkey_packet(
    packet: pgp::packet::SecretSubkey,
    version: PgpPacketHeaderVersion,
) -> PyResult<pgp::packet::SecretSubkey> {
    if packet.packet_header_version() == version {
        return Ok(packet);
    }

    let body = serialize_packet_body(&packet)?;
    let header = packet_header_from_body_len(version, Tag::SecretSubkey, body.len())?;
    pgp::packet::SecretSubkey::try_from_reader(header, Cursor::new(body.as_slice()))
        .map_err(to_py_err)
}

#[derive(Clone)]
struct KeyPacketVersions {
    primary: PgpPacketHeaderVersion,
    subkeys: Vec<PgpPacketHeaderVersion>,
}

fn apply_generated_key_packet_versions(
    key: SignedSecretKey,
    packet_versions: &KeyPacketVersions,
) -> PyResult<SignedSecretKey> {
    let SignedSecretKey {
        primary_key,
        details,
        public_subkeys,
        secret_subkeys,
    } = key;

    if secret_subkeys.len() != packet_versions.subkeys.len() {
        return Err(to_py_err(format!(
            "generated subkey count mismatch: expected {}, got {}",
            packet_versions.subkeys.len(),
            secret_subkeys.len(),
        )));
    }

    let primary_key = reframe_secret_key_packet(primary_key, packet_versions.primary)?;
    let secret_subkeys = secret_subkeys
        .into_iter()
        .zip(packet_versions.subkeys.iter().copied())
        .map(|(mut subkey, version)| {
            subkey.key = reframe_secret_subkey_packet(subkey.key, version)?;
            Ok(subkey)
        })
        .collect::<PyResult<Vec<_>>>()?;

    Ok(SignedSecretKey {
        primary_key,
        details,
        public_subkeys,
        secret_subkeys,
    })
}

fn s2k_params_from_secret_params(secret_params: &PgpSecretParams) -> PyS2kParams {
    let inner = match secret_params {
        PgpSecretParams::Plain(_) => PgpS2kParams::Unprotected,
        PgpSecretParams::Encrypted(params) => params.string_to_key_params().clone(),
    };
    PyS2kParams { inner }
}

fn signature_version_number(version: SignatureVersion) -> u8 {
    match version {
        SignatureVersion::V2 => 2,
        SignatureVersion::V3 => 3,
        SignatureVersion::V4 => 4,
        SignatureVersion::V5 => 5,
        SignatureVersion::V6 => 6,
        SignatureVersion::Other(value) => value,
    }
}

fn signature_type_name(signature_type: SignatureType) -> String {
    match signature_type {
        SignatureType::Binary => "binary",
        SignatureType::Text => "text",
        SignatureType::Standalone => "standalone",
        SignatureType::CertGeneric => "cert-generic",
        SignatureType::CertPersona => "cert-persona",
        SignatureType::CertCasual => "cert-casual",
        SignatureType::CertPositive => "cert-positive",
        SignatureType::SubkeyBinding => "subkey-binding",
        SignatureType::KeyBinding => "primary-key-binding",
        SignatureType::Key => "direct-key",
        SignatureType::KeyRevocation => "key-revocation",
        SignatureType::SubkeyRevocation => "subkey-revocation",
        SignatureType::CertRevocation => "cert-revocation",
        SignatureType::Timestamp => "timestamp",
        SignatureType::ThirdParty => "third-party",
        SignatureType::Other(_) => "other",
    }
    .to_string()
}

fn signature_salt(signature: &Signature) -> Option<Vec<u8>> {
    signature
        .config()
        .and_then(|config| match &config.version_specific {
            SignatureVersionSpecific::V6 { salt } => Some(salt.clone()),
            _ => None,
        })
}

fn key_flags_info_from_key_flags(key_flags: &PgpKeyFlags) -> KeyFlagsInfo {
    KeyFlagsInfo {
        certify: key_flags.certify(),
        sign: key_flags.sign(),
        encrypt_communications: key_flags.encrypt_comms(),
        encrypt_storage: key_flags.encrypt_storage(),
        authenticate: key_flags.authentication(),
        shared: key_flags.shared(),
        draft_decrypt_forwarded: key_flags.draft_decrypt_forwarded(),
        group: key_flags.group(),
        adsk: key_flags.adsk(),
        timestamping: key_flags.timestamping(),
    }
}

fn features_info_from_features(features: &PgpFeatures) -> FeaturesInfo {
    FeaturesInfo {
        seipd_v1: features.seipd_v1(),
        seipd_v2: features.seipd_v2(),
    }
}

fn signature_info_from_signature(signature: &Signature, is_one_pass: bool) -> SignatureInfo {
    let key_flags = signature.key_flags();
    SignatureInfo {
        version: signature_version_number(signature.version()),
        signature_type: signature.typ().map(signature_type_name),
        hash_algorithm: signature.hash_alg().map(|algorithm| algorithm.to_string()),
        public_key_algorithm: signature
            .config()
            .map(|config| format!("{:?}", config.pub_alg)),
        issuer_key_ids: signature
            .issuer_key_id()
            .iter()
            .map(|key_id| key_id.to_string())
            .collect(),
        issuer_fingerprints: signature
            .issuer_fingerprint()
            .iter()
            .map(|fingerprint| fingerprint.to_string())
            .collect(),
        creation_time: signature.created().map(|timestamp| timestamp.as_secs()),
        signature_expiration_seconds: signature
            .signature_expiration_time()
            .map(|duration| duration.as_secs()),
        signer_user_id: signature
            .signers_userid()
            .map(|user_id| String::from_utf8_lossy(user_id.as_ref()).into_owned()),
        signed_hash_value: signature
            .signed_hash_value()
            .map(|signed_hash_value| signed_hash_value.to_vec()),
        salt: signature_salt(signature),
        preferred_symmetric_algorithms: symmetric_algorithm_names(
            signature.preferred_symmetric_algs(),
        ),
        preferred_hash_algorithms: hash_algorithm_names(signature.preferred_hash_algs()),
        preferred_compression_algorithms: compression_algorithm_names(
            signature.preferred_compression_algs(),
        ),
        preferred_aead_algorithms: aead_algorithm_preference_names(signature.preferred_aead_algs()),
        key_flags: key_flags_info_from_key_flags(&key_flags),
        features: signature.features().map(features_info_from_features),
        embedded_signature: signature
            .embedded_signature()
            .map(|embedded| Box::new(signature_info_from_signature(embedded, false))),
        is_one_pass,
    }
}

fn signature_info_from_full_signature(signature: &FullSignaturePacket) -> SignatureInfo {
    let is_one_pass = matches!(signature, FullSignaturePacket::Ops { .. });
    signature_info_from_signature(signature.signature(), is_one_pass)
}

fn direct_signature_infos_from_details(
    details: &pgp::composed::SignedKeyDetails,
) -> Vec<SignatureInfo> {
    details
        .direct_signatures
        .iter()
        .map(|signature| signature_info_from_signature(signature, false))
        .collect::<Vec<_>>()
}

fn user_binding_info_from_signed_user(user: &pgp::types::SignedUser) -> UserBindingInfo {
    UserBindingInfo {
        user_id: String::from_utf8_lossy(user.id.id()).into_owned(),
        is_primary: user.is_primary(),
        signatures: user
            .signatures
            .iter()
            .map(|signature| signature_info_from_signature(signature, false))
            .collect::<Vec<_>>(),
    }
}

fn user_binding_infos_from_details(
    details: &pgp::composed::SignedKeyDetails,
) -> Vec<UserBindingInfo> {
    details
        .users
        .iter()
        .map(user_binding_info_from_signed_user)
        .collect::<Vec<_>>()
}

fn user_attribute_binding_info_from_signed_user_attribute(
    attribute: &pgp::types::SignedUserAttribute,
) -> UserAttributeBindingInfo {
    UserAttributeBindingInfo {
        user_attribute: UserAttribute {
            inner: attribute.attr.clone(),
        },
        signatures: attribute
            .signatures
            .iter()
            .map(|signature| signature_info_from_signature(signature, false))
            .collect::<Vec<_>>(),
    }
}

fn user_attribute_binding_infos_from_details(
    details: &pgp::composed::SignedKeyDetails,
) -> Vec<UserAttributeBindingInfo> {
    details
        .user_attributes
        .iter()
        .map(user_attribute_binding_info_from_signed_user_attribute)
        .collect::<Vec<_>>()
}

fn subkey_binding_info_from_signed_public_subkey(subkey: &SignedPublicSubKey) -> SubkeyBindingInfo {
    SubkeyBindingInfo {
        fingerprint: subkey.key.fingerprint().to_string(),
        key_id: subkey.key.legacy_key_id().to_string(),
        version: key_version_number(subkey.key.version()),
        created_at: subkey.key.created_at().as_secs(),
        public_key_algorithm: public_key_algorithm_name(subkey.key.algorithm()).to_string(),
        public_params: public_params_info_from_params(subkey.key.public_params()),
        packet_version: subkey.key.packet_header_version(),
        signatures: subkey
            .signatures
            .iter()
            .map(|signature| signature_info_from_signature(signature, false))
            .collect::<Vec<_>>(),
    }
}

fn subkey_binding_info_from_signed_secret_subkey(subkey: &SignedSecretSubKey) -> SubkeyBindingInfo {
    SubkeyBindingInfo {
        fingerprint: subkey.key.public_key().fingerprint().to_string(),
        key_id: subkey.key.public_key().legacy_key_id().to_string(),
        version: key_version_number(subkey.key.version()),
        created_at: subkey.key.created_at().as_secs(),
        public_key_algorithm: public_key_algorithm_name(subkey.key.algorithm()).to_string(),
        public_params: public_params_info_from_params(subkey.key.public_params()),
        packet_version: subkey.key.packet_header_version(),
        signatures: subkey
            .signatures
            .iter()
            .map(|signature| signature_info_from_signature(signature, false))
            .collect::<Vec<_>>(),
    }
}

#[derive(Clone)]
struct DecryptedSignature {
    signature: Signature,
    is_one_pass: bool,
}

fn decrypted_signature_from_full_signature(signature: &FullSignaturePacket) -> DecryptedSignature {
    DecryptedSignature {
        signature: signature.signature().clone(),
        is_one_pass: matches!(signature, FullSignaturePacket::Ops { .. }),
    }
}

fn signature_info_from_decrypted_signature(signature: &DecryptedSignature) -> SignatureInfo {
    signature_info_from_signature(&signature.signature, signature.is_one_pass)
}

#[derive(Clone, Copy)]
enum EncryptionVersion {
    SeipdV1,
    SeipdV2,
}

fn encryption_version_from_name(name: &str) -> PyResult<EncryptionVersion> {
    match name.to_ascii_lowercase().as_str() {
        "seipd-v1" => Ok(EncryptionVersion::SeipdV1),
        "seipd-v2" => Ok(EncryptionVersion::SeipdV2),
        _ => Err(to_py_err(
            "unsupported encryption container; expected 'seipd-v1' or 'seipd-v2'",
        )),
    }
}

fn symmetric_algorithm_from_name(name: &str) -> PyResult<SymmetricKeyAlgorithm> {
    match name.to_ascii_lowercase().as_str() {
        "aes128" => Ok(SymmetricKeyAlgorithm::AES128),
        "aes192" => Ok(SymmetricKeyAlgorithm::AES192),
        "aes256" => Ok(SymmetricKeyAlgorithm::AES256),
        _ => Err(to_py_err(
            "unsupported symmetric algorithm; expected 'aes128', 'aes192', or 'aes256'",
        )),
    }
}

fn aead_algorithm_from_name(name: &str) -> PyResult<AeadAlgorithm> {
    match name.to_ascii_lowercase().as_str() {
        "eax" => Ok(AeadAlgorithm::Eax),
        "ocb" => Ok(AeadAlgorithm::Ocb),
        "gcm" => Ok(AeadAlgorithm::Gcm),
        _ => Err(to_py_err(
            "unsupported AEAD algorithm; expected 'eax', 'ocb', or 'gcm'",
        )),
    }
}

fn compression_algorithm_from_name(name: Option<&str>) -> PyResult<Option<CompressionAlgorithm>> {
    match name.map(str::to_ascii_lowercase).as_deref() {
        None => Ok(None),
        Some("zip") => Ok(Some(CompressionAlgorithm::ZIP)),
        Some("zlib") => Ok(Some(CompressionAlgorithm::ZLIB)),
        Some("bzip2") => Ok(Some(CompressionAlgorithm::BZip2)),
        _ => Err(to_py_err(
            "unsupported compression algorithm; expected 'zip', 'zlib', or 'bzip2'",
        )),
    }
}

macro_rules! encrypt_to_recipient {
    ($builder:expr, $recipient:expr) => {{
        let recipient = &$recipient.inner;
        if let Some(subkey) = recipient
            .public_subkeys
            .iter()
            .find(|subkey| subkey.algorithm().can_encrypt())
        {
            $builder
                .encrypt_to_key(rand::thread_rng(), subkey)
                .map_err(to_py_err)?;
        } else if recipient.algorithm().can_encrypt() {
            $builder
                .encrypt_to_key(rand::thread_rng(), recipient)
                .map_err(to_py_err)?;
        } else {
            return Err(to_py_err(
                "public key does not contain an encryption-capable primary key or subkey",
            ));
        }
    }};
}

/// Packet-header framing for transferable key packets.
///
/// RFC 9580 distinguishes between the legacy "old" header format and the current "new" header
/// format. rPGP exposes this via `types::PacketHeaderVersion`; the key builders use the selected
/// value when serializing primary-key and subkey packets.
#[pyclass(module = "openpgp", name = "PacketHeaderVersion")]
#[derive(Clone, Copy, PartialEq, Eq)]
struct PyPacketHeaderVersion {
    inner: PgpPacketHeaderVersion,
}

#[pymethods]
impl PyPacketHeaderVersion {
    #[staticmethod]
    fn old() -> Self {
        Self {
            inner: PgpPacketHeaderVersion::Old,
        }
    }

    #[staticmethod]
    #[pyo3(name = "new")]
    fn new_() -> Self {
        Self {
            inner: PgpPacketHeaderVersion::New,
        }
    }

    /// Return the normalized RFC 9580 packet-header variant name.
    #[getter]
    fn name(&self) -> &'static str {
        packet_header_version_name(self.inner)
    }

    fn __richcmp__(&self, other: PyRef<'_, Self>, op: CompareOp) -> bool {
        match op {
            CompareOp::Eq => self.inner == other.inner,
            CompareOp::Ne => self.inner != other.inner,
            _ => false,
        }
    }

    fn __repr__(&self) -> String {
        format!("PacketHeaderVersion.{}()", self.name())
    }
}

/// Key-flag configuration for encryption-capable OpenPGP keys.
///
/// This mirrors rPGP's `EncryptionCaps` builder enum and RFC 9580 key-flags semantics for the
/// "encrypt communications" and "encrypt storage" flags.
#[pyclass(module = "openpgp")]
#[derive(Clone, Copy)]
struct EncryptionCaps {
    inner: PgpEncryptionCaps,
}

#[pymethods]
impl EncryptionCaps {
    #[staticmethod]
    fn none() -> Self {
        Self {
            inner: PgpEncryptionCaps::None,
        }
    }

    #[staticmethod]
    fn communication() -> Self {
        Self {
            inner: PgpEncryptionCaps::Communication,
        }
    }

    #[staticmethod]
    fn storage() -> Self {
        Self {
            inner: PgpEncryptionCaps::Storage,
        }
    }

    #[staticmethod]
    fn all() -> Self {
        Self {
            inner: PgpEncryptionCaps::All,
        }
    }

    fn __repr__(&self) -> String {
        let name = match self.inner {
            PgpEncryptionCaps::None => "none",
            PgpEncryptionCaps::Communication => "communication",
            PgpEncryptionCaps::Storage => "storage",
            PgpEncryptionCaps::All => "all",
        };
        format!("EncryptionCaps.{name}()")
    }
}

/// An asymmetric algorithm configuration for OpenPGP key generation.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct KeyType {
    inner: PgpKeyType,
}

#[pymethods]
impl KeyType {
    #[staticmethod]
    fn rsa(bits: u32) -> Self {
        Self {
            inner: PgpKeyType::Rsa(bits),
        }
    }

    #[staticmethod]
    fn dsa(bits: u32) -> PyResult<Self> {
        Ok(Self {
            inner: PgpKeyType::Dsa(dsa_key_size_from_bits(bits)?),
        })
    }

    #[staticmethod]
    fn ed25519_legacy() -> Self {
        Self {
            inner: PgpKeyType::Ed25519Legacy,
        }
    }

    #[staticmethod]
    fn ed25519() -> Self {
        Self {
            inner: PgpKeyType::Ed25519,
        }
    }

    #[staticmethod]
    fn ed448() -> Self {
        Self {
            inner: PgpKeyType::Ed448,
        }
    }

    #[staticmethod]
    fn ecdsa(curve: &str) -> PyResult<Self> {
        Ok(Self {
            inner: PgpKeyType::ECDSA(curve_from_name(curve)?),
        })
    }

    #[staticmethod]
    fn ecdh(curve: &str) -> PyResult<Self> {
        Ok(Self {
            inner: PgpKeyType::ECDH(curve_from_name(curve)?),
        })
    }

    #[staticmethod]
    fn x25519() -> Self {
        Self {
            inner: PgpKeyType::X25519,
        }
    }

    #[staticmethod]
    fn x448() -> Self {
        Self {
            inner: PgpKeyType::X448,
        }
    }

    fn can_sign(&self) -> bool {
        self.inner.can_sign()
    }

    fn can_encrypt(&self) -> bool {
        self.inner.can_encrypt()
    }

    fn __repr__(&self) -> String {
        format!("KeyType.{}", key_type_name(&self.inner))
    }
}

/// A parsed or constructed RFC 9580 String-to-Key (S2K) specifier.
#[pyclass(module = "openpgp", name = "StringToKey")]
#[derive(Clone)]
struct PyStringToKey {
    inner: PgpStringToKey,
}

#[pymethods]
impl PyStringToKey {
    /// Create an iterated-and-salted S2K specifier (type 3).
    ///
    /// ``count`` is the encoded iteration-count octet from RFC 9580 section 3.7.1.3.
    #[staticmethod]
    #[pyo3(signature = (hash_algorithm, count, salt=None))]
    fn iterated(hash_algorithm: &str, count: u8, salt: Option<&[u8]>) -> PyResult<Self> {
        Ok(Self {
            inner: PgpStringToKey::IteratedAndSalted {
                hash_alg: hash_algorithm_from_name(hash_algorithm)?,
                salt: exact_or_random_array::<8>(salt, "salt")?,
                count,
            },
        })
    }

    /// Create an Argon2 S2K specifier (type 4).
    ///
    /// The parameters correspond to RFC 9580 section 3.7.1.4 and RFC 9106 section 4.5.
    #[staticmethod]
    #[pyo3(signature = (passes, parallelism, memory_exponent, salt=None))]
    fn argon2(
        passes: u8,
        parallelism: u8,
        memory_exponent: u8,
        salt: Option<&[u8]>,
    ) -> PyResult<Self> {
        Ok(Self {
            inner: PgpStringToKey::Argon2 {
                salt: exact_or_random_array::<16>(salt, "salt")?,
                t: passes,
                p: parallelism,
                m_enc: memory_exponent,
            },
        })
    }

    /// Return the numeric S2K type identifier from RFC 9580 section 3.7.1.
    #[getter]
    fn type_id(&self) -> u8 {
        self.inner.id()
    }

    /// Return a normalized name for the wrapped S2K variant.
    #[getter]
    fn kind(&self) -> String {
        string_to_key_kind_name(&self.inner).to_string()
    }

    /// Return the hash algorithm name for hash-based S2K variants, if present.
    #[getter]
    fn hash_algorithm(&self) -> Option<String> {
        match &self.inner {
            PgpStringToKey::Simple { hash_alg }
            | PgpStringToKey::Salted { hash_alg, .. }
            | PgpStringToKey::IteratedAndSalted { hash_alg, .. } => {
                Some(normalized_algorithm_name(hash_alg))
            }
            _ => None,
        }
    }

    /// Return the salt bytes for salted S2K variants, if present.
    #[getter]
    fn salt(&self) -> Option<Vec<u8>> {
        match &self.inner {
            PgpStringToKey::Salted { salt, .. }
            | PgpStringToKey::IteratedAndSalted { salt, .. } => Some(salt.to_vec()),
            PgpStringToKey::Argon2 { salt, .. } => Some(salt.to_vec()),
            _ => None,
        }
    }

    /// Return the encoded iteration-count octet for iterated-and-salted S2K variants.
    #[getter]
    fn count(&self) -> Option<u8> {
        match &self.inner {
            PgpStringToKey::IteratedAndSalted { count, .. } => Some(*count),
            _ => None,
        }
    }

    /// Return the Argon2 pass count ``t``, if present.
    #[getter]
    fn passes(&self) -> Option<u8> {
        match &self.inner {
            PgpStringToKey::Argon2 { t, .. } => Some(*t),
            _ => None,
        }
    }

    /// Return the Argon2 degree of parallelism ``p``, if present.
    #[getter]
    fn parallelism(&self) -> Option<u8> {
        match &self.inner {
            PgpStringToKey::Argon2 { p, .. } => Some(*p),
            _ => None,
        }
    }

    /// Return the Argon2 encoded memory exponent ``m`` , if present.
    #[getter]
    fn memory_exponent(&self) -> Option<u8> {
        match &self.inner {
            PgpStringToKey::Argon2 { m_enc, .. } => Some(*m_enc),
            _ => None,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "StringToKey(kind='{}', type_id={})",
            self.kind(),
            self.type_id()
        )
    }
}

/// Parsed or constructed secret-key protection parameters (RFC 9580 section 3.7.2).
#[pyclass(module = "openpgp", name = "S2kParams")]
#[derive(Clone)]
struct PyS2kParams {
    inner: PgpS2kParams,
}

#[pymethods]
impl PyS2kParams {
    /// Create CFB-based secret-key protection parameters (usage 254).
    ///
    /// RFC 9580 forbids combining Argon2 S2K with non-AEAD usage modes.
    #[staticmethod]
    #[pyo3(signature = (symmetric_algorithm, string_to_key, iv=None))]
    fn cfb(
        symmetric_algorithm: &str,
        string_to_key: PyRef<'_, PyStringToKey>,
        iv: Option<&[u8]>,
    ) -> PyResult<Self> {
        if matches!(&string_to_key.inner, PgpStringToKey::Argon2 { .. }) {
            return Err(to_py_err(
                "Argon2 String-to-Key may only be used with AEAD S2K parameters",
            ));
        }

        let sym_alg = symmetric_algorithm_from_name(symmetric_algorithm)?;
        let iv = exact_or_random_vec(iv, sym_alg.block_size(), "iv")?;
        Ok(Self {
            inner: PgpS2kParams::Cfb {
                sym_alg,
                s2k: string_to_key.inner.clone(),
                iv: iv.into(),
            },
        })
    }

    /// Create AEAD-based secret-key protection parameters (usage 253).
    #[staticmethod]
    #[pyo3(signature = (symmetric_algorithm, aead_algorithm, string_to_key, nonce=None))]
    fn aead(
        symmetric_algorithm: &str,
        aead_algorithm: &str,
        string_to_key: PyRef<'_, PyStringToKey>,
        nonce: Option<&[u8]>,
    ) -> PyResult<Self> {
        let sym_alg = symmetric_algorithm_from_name(symmetric_algorithm)?;
        let aead_mode = aead_algorithm_from_name(aead_algorithm)?;
        let nonce = exact_or_random_vec(nonce, aead_mode.nonce_size(), "nonce")?;
        Ok(Self {
            inner: PgpS2kParams::Aead {
                sym_alg,
                aead_mode,
                s2k: string_to_key.inner.clone(),
                nonce: nonce.into(),
            },
        })
    }

    /// Return the numeric S2K-usage octet from RFC 9580 section 3.7.2.
    #[getter]
    fn usage_id(&self) -> u8 {
        (&self.inner).into()
    }

    /// Return a normalized name for the wrapped S2K usage mode.
    #[getter]
    fn usage(&self) -> String {
        s2k_usage_name(&self.inner).to_string()
    }

    /// Return the symmetric algorithm used to encrypt the secret material, if present.
    #[getter]
    fn symmetric_algorithm(&self) -> Option<String> {
        match &self.inner {
            PgpS2kParams::Unprotected => None,
            PgpS2kParams::LegacyCfb { sym_alg, .. }
            | PgpS2kParams::Aead { sym_alg, .. }
            | PgpS2kParams::Cfb { sym_alg, .. }
            | PgpS2kParams::MalleableCfb { sym_alg, .. } => {
                Some(normalized_algorithm_name(sym_alg))
            }
        }
    }

    /// Return the AEAD algorithm name for AEAD-protected secret material, if present.
    #[getter]
    fn aead_algorithm(&self) -> Option<String> {
        match &self.inner {
            PgpS2kParams::Aead { aead_mode, .. } => Some(normalized_algorithm_name(aead_mode)),
            _ => None,
        }
    }

    /// Return the wrapped String-to-Key specifier, if this usage mode carries one.
    #[getter]
    fn string_to_key(&self) -> Option<PyStringToKey> {
        match &self.inner {
            PgpS2kParams::Aead { s2k, .. }
            | PgpS2kParams::Cfb { s2k, .. }
            | PgpS2kParams::MalleableCfb { s2k, .. } => Some(PyStringToKey { inner: s2k.clone() }),
            _ => None,
        }
    }

    /// Return the initialization vector for CFB-based modes, if present.
    #[getter]
    fn iv(&self) -> Option<Vec<u8>> {
        match &self.inner {
            PgpS2kParams::LegacyCfb { iv, .. }
            | PgpS2kParams::Cfb { iv, .. }
            | PgpS2kParams::MalleableCfb { iv, .. } => Some(iv.to_vec()),
            _ => None,
        }
    }

    /// Return the AEAD nonce, if present.
    #[getter]
    fn nonce(&self) -> Option<Vec<u8>> {
        match &self.inner {
            PgpS2kParams::Aead { nonce, .. } => Some(nonce.to_vec()),
            _ => None,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "S2kParams(usage='{}', usage_id={})",
            self.usage(),
            self.usage_id()
        )
    }
}

/// Built subkey-generation parameters.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct SubkeyParams {
    inner: PgpSubkeyParams,
    packet_version: PgpPacketHeaderVersion,
}

#[pymethods]
impl SubkeyParams {
    fn __repr__(&self) -> String {
        "SubkeyParams()".to_string()
    }
}

/// Builder for subkey-generation parameters.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct SubkeyParamsBuilder {
    inner: PgpSubkeyParamsBuilder,
    packet_version: PgpPacketHeaderVersion,
}

#[pymethods]
impl SubkeyParamsBuilder {
    #[new]
    fn new() -> Self {
        Self {
            inner: PgpSubkeyParamsBuilder::default(),
            packet_version: PgpPacketHeaderVersion::New,
        }
    }

    fn version<'py>(mut slf: PyRefMut<'py, Self>, value: u8) -> PyResult<PyRefMut<'py, Self>> {
        slf.inner.version(key_version_from_number(value)?);
        Ok(slf)
    }

    fn key_type<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, KeyType>,
    ) -> PyRefMut<'py, Self> {
        slf.inner.key_type(value.inner.clone());
        slf
    }

    fn can_sign<'py>(mut slf: PyRefMut<'py, Self>, value: bool) -> PyRefMut<'py, Self> {
        slf.inner.can_sign(value);
        slf
    }

    fn can_encrypt<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, EncryptionCaps>,
    ) -> PyRefMut<'py, Self> {
        slf.inner.can_encrypt(value.inner);
        slf
    }

    fn can_authenticate<'py>(mut slf: PyRefMut<'py, Self>, value: bool) -> PyRefMut<'py, Self> {
        slf.inner.can_authenticate(value);
        slf
    }

    fn created_at<'py>(mut slf: PyRefMut<'py, Self>, value: u32) -> PyRefMut<'py, Self> {
        slf.inner.created_at(timestamp_from_seconds(value));
        slf
    }

    /// Select the RFC 9580 packet-header framing used when serializing this subkey packet.
    fn packet_version<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, PyPacketHeaderVersion>,
    ) -> PyRefMut<'py, Self> {
        slf.packet_version = value.inner;
        slf.inner.packet_version(value.inner);
        slf
    }

    fn passphrase<'py>(mut slf: PyRefMut<'py, Self>, value: Option<&str>) -> PyRefMut<'py, Self> {
        slf.inner.passphrase(value.map(str::to_owned));
        slf
    }

    /// Override the secret-key protection parameters for this subkey.
    fn s2k<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, PyS2kParams>,
    ) -> PyRefMut<'py, Self> {
        slf.inner.s2k(Some(value.inner.clone()));
        slf
    }

    fn build(&self) -> PyResult<SubkeyParams> {
        let inner = self.inner.build().map_err(to_py_err)?;
        Ok(SubkeyParams {
            inner,
            packet_version: self.packet_version,
        })
    }

    fn __repr__(&self) -> String {
        "SubkeyParamsBuilder()".to_string()
    }
}

/// Built primary-key generation parameters.
#[pyclass(module = "openpgp")]
struct SecretKeyParams {
    inner: Mutex<Option<PgpSecretKeyParams>>,
    packet_versions: KeyPacketVersions,
}

#[pymethods]
impl SecretKeyParams {
    fn generate(&self) -> PyResult<SecretKey> {
        let params = self
            .inner
            .lock()
            .map_err(|_| to_py_err("key parameter state is unavailable"))?
            .take()
            .ok_or_else(|| to_py_err("key parameters have already been consumed"))?;
        let inner = params.generate(rand::thread_rng()).map_err(to_py_err)?;
        let inner = apply_generated_key_packet_versions(inner, &self.packet_versions)?;
        Ok(SecretKey { inner })
    }

    fn __repr__(&self) -> String {
        let consumed = self
            .inner
            .lock()
            .map(|guard| guard.is_none())
            .unwrap_or(true);
        format!("SecretKeyParams(consumed={consumed})")
    }
}

/// Builder for primary-key generation parameters.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct SecretKeyParamsBuilder {
    inner: PgpSecretKeyParamsBuilder,
    user_attributes: Vec<PgpUserAttribute>,
    packet_version: PgpPacketHeaderVersion,
    subkey_packet_versions: Vec<PgpPacketHeaderVersion>,
}

#[pymethods]
impl SecretKeyParamsBuilder {
    #[new]
    fn new() -> Self {
        Self {
            inner: PgpSecretKeyParamsBuilder::default(),
            user_attributes: Vec::new(),
            packet_version: PgpPacketHeaderVersion::New,
            subkey_packet_versions: Vec::new(),
        }
    }

    fn version<'py>(mut slf: PyRefMut<'py, Self>, value: u8) -> PyResult<PyRefMut<'py, Self>> {
        slf.inner.version(key_version_from_number(value)?);
        Ok(slf)
    }

    fn key_type<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, KeyType>,
    ) -> PyRefMut<'py, Self> {
        slf.inner.key_type(value.inner.clone());
        slf
    }

    fn can_sign<'py>(mut slf: PyRefMut<'py, Self>, value: bool) -> PyRefMut<'py, Self> {
        slf.inner.can_sign(value);
        slf
    }

    fn can_certify<'py>(mut slf: PyRefMut<'py, Self>, value: bool) -> PyRefMut<'py, Self> {
        slf.inner.can_certify(value);
        slf
    }

    fn can_encrypt<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, EncryptionCaps>,
    ) -> PyRefMut<'py, Self> {
        slf.inner.can_encrypt(value.inner);
        slf
    }

    fn can_authenticate<'py>(mut slf: PyRefMut<'py, Self>, value: bool) -> PyRefMut<'py, Self> {
        slf.inner.can_authenticate(value);
        slf
    }

    fn created_at<'py>(mut slf: PyRefMut<'py, Self>, value: u32) -> PyRefMut<'py, Self> {
        slf.inner.created_at(timestamp_from_seconds(value));
        slf
    }

    /// Select the RFC 9580 packet-header framing used when serializing the primary key packet.
    fn packet_version<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, PyPacketHeaderVersion>,
    ) -> PyRefMut<'py, Self> {
        slf.packet_version = value.inner;
        slf.inner.packet_version(value.inner);
        slf
    }

    fn feature_seipd_v1<'py>(mut slf: PyRefMut<'py, Self>, value: bool) -> PyRefMut<'py, Self> {
        slf.inner.feature_seipd_v1(value);
        slf
    }

    fn feature_seipd_v2<'py>(mut slf: PyRefMut<'py, Self>, value: bool) -> PyRefMut<'py, Self> {
        slf.inner.feature_seipd_v2(value);
        slf
    }

    fn preferred_symmetric_algorithms<'py>(
        mut slf: PyRefMut<'py, Self>,
        values: Vec<String>,
    ) -> PyResult<PyRefMut<'py, Self>> {
        slf.inner
            .preferred_symmetric_algorithms(symmetric_algorithms_from_names(values)?);
        Ok(slf)
    }

    fn preferred_hash_algorithms<'py>(
        mut slf: PyRefMut<'py, Self>,
        values: Vec<String>,
    ) -> PyResult<PyRefMut<'py, Self>> {
        slf.inner
            .preferred_hash_algorithms(hash_algorithms_from_names(values)?);
        Ok(slf)
    }

    fn preferred_compression_algorithms<'py>(
        mut slf: PyRefMut<'py, Self>,
        values: Vec<String>,
    ) -> PyResult<PyRefMut<'py, Self>> {
        slf.inner
            .preferred_compression_algorithms(compression_algorithms_from_names(values)?);
        Ok(slf)
    }

    fn preferred_aead_algorithms<'py>(
        mut slf: PyRefMut<'py, Self>,
        values: Vec<(String, String)>,
    ) -> PyResult<PyRefMut<'py, Self>> {
        slf.inner
            .preferred_aead_algorithms(aead_algorithm_preferences_from_names(values)?);
        Ok(slf)
    }

    fn passphrase<'py>(mut slf: PyRefMut<'py, Self>, value: Option<&str>) -> PyRefMut<'py, Self> {
        slf.inner.passphrase(value.map(str::to_owned));
        slf
    }

    /// Override the secret-key protection parameters for the primary key packet.
    fn s2k<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, PyS2kParams>,
    ) -> PyRefMut<'py, Self> {
        slf.inner.s2k(Some(value.inner.clone()));
        slf
    }

    fn primary_user_id<'py>(mut slf: PyRefMut<'py, Self>, value: &str) -> PyRefMut<'py, Self> {
        slf.inner.primary_user_id(value.to_string());
        slf
    }

    fn user_id<'py>(mut slf: PyRefMut<'py, Self>, value: &str) -> PyRefMut<'py, Self> {
        slf.inner.user_id(value.to_string());
        slf
    }

    fn user_ids<'py>(mut slf: PyRefMut<'py, Self>, values: Vec<String>) -> PyRefMut<'py, Self> {
        slf.inner.user_ids(values);
        slf
    }

    /// Add a single RFC 9580 user attribute that will be self-certified on the certificate.
    fn user_attribute<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, UserAttribute>,
    ) -> PyRefMut<'py, Self> {
        slf.user_attributes.push(value.inner.clone());
        slf
    }

    /// Replace the builder's user-attribute list with the provided sequence.
    fn user_attributes<'py>(
        mut slf: PyRefMut<'py, Self>,
        values: Vec<PyRef<'_, UserAttribute>>,
    ) -> PyRefMut<'py, Self> {
        slf.user_attributes = values
            .into_iter()
            .map(|value| value.inner.clone())
            .collect();
        slf
    }

    fn subkey<'py>(
        mut slf: PyRefMut<'py, Self>,
        value: PyRef<'_, SubkeyParams>,
    ) -> PyRefMut<'py, Self> {
        slf.subkey_packet_versions.push(value.packet_version);
        slf.inner.subkey(value.inner.clone());
        slf
    }

    fn build(&self) -> PyResult<SecretKeyParams> {
        let mut inner_builder = self.inner.clone();
        inner_builder.user_attributes(self.user_attributes.clone());
        let inner = inner_builder.build().map_err(to_py_err)?;
        Ok(SecretKeyParams {
            inner: Mutex::new(Some(inner)),
            packet_versions: KeyPacketVersions {
                primary: self.packet_version,
                subkeys: self.subkey_packet_versions.clone(),
            },
        })
    }

    fn generate(&self) -> PyResult<SecretKey> {
        self.build()?.generate()
    }

    fn __repr__(&self) -> String {
        "SecretKeyParamsBuilder()".to_string()
    }
}

/// A transferable OpenPGP public key (certificate) as defined by RFC 9580.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct PublicKey {
    inner: SignedPublicKey,
}

#[pymethods]
impl PublicKey {
    /// Parse an ASCII-armored transferable public key.
    #[staticmethod]
    fn from_armor(data: &str) -> PyResult<(Self, Headers)> {
        let (inner, headers) = SignedPublicKey::from_string(data).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    /// Parse a binary transferable public key.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = SignedPublicKey::from_bytes(Cursor::new(data)).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// The RFC 9580 fingerprint of the primary key.
    #[getter]
    fn fingerprint(&self) -> String {
        self.inner.fingerprint().to_string()
    }

    /// The legacy key identifier of the primary key.
    #[getter]
    fn key_id(&self) -> String {
        self.inner.legacy_key_id().to_string()
    }

    /// The OpenPGP key-packet version number of the primary key.
    #[getter]
    fn version(&self) -> u8 {
        key_version_number(self.inner.primary_key.version())
    }

    /// The primary key packet's creation time as seconds since the Unix epoch.
    #[getter]
    fn created_at(&self) -> u32 {
        self.inner.primary_key.created_at().as_secs()
    }

    /// The primary key packet's public-key algorithm.
    #[getter]
    fn public_key_algorithm(&self) -> String {
        public_key_algorithm_name(self.inner.primary_key.algorithm()).to_string()
    }

    /// Structured algorithm-specific public-key metadata from `KeyDetails.public_params()`.
    #[getter]
    fn public_params(&self) -> PublicParamsInfo {
        public_params_info_from_params(self.inner.primary_key.public_params())
    }

    /// The RFC 9580 packet-header framing used by the primary key packet.
    #[getter]
    fn packet_version(&self) -> PyPacketHeaderVersion {
        PyPacketHeaderVersion {
            inner: self.inner.primary_key.packet_header_version(),
        }
    }

    /// The number of public subkeys attached to the certificate.
    #[getter]
    fn public_subkey_count(&self) -> usize {
        self.inner.public_subkeys.len()
    }

    /// UTF-8 decoded user IDs, with invalid octets replaced lossily.
    #[getter]
    fn user_ids(&self) -> Vec<String> {
        lossy_user_ids(&self.inner.details)
    }

    /// Return direct-key self-signature metadata attached to the certificate.
    ///
    /// RFC 9580 version-6 certificates place certificate-wide preferences, key flags, and
    /// feature advertisements on these direct-key signatures.
    fn direct_signature_infos(&self) -> Vec<SignatureInfo> {
        direct_signature_infos_from_details(&self.inner.details)
    }

    /// Return user IDs together with their certification self-signatures.
    ///
    /// Version-4 certificates carry certificate metadata such as key flags and preferred
    /// algorithms on the primary user-ID binding signature.
    fn user_bindings(&self) -> Vec<UserBindingInfo> {
        user_binding_infos_from_details(&self.inner.details)
    }

    /// Return user attributes together with their certification self-signatures.
    fn user_attribute_bindings(&self) -> Vec<UserAttributeBindingInfo> {
        user_attribute_binding_infos_from_details(&self.inner.details)
    }

    /// Return public subkeys together with their binding-signature metadata.
    fn subkey_bindings(&self) -> Vec<SubkeyBindingInfo> {
        self.inner
            .public_subkeys
            .iter()
            .map(subkey_binding_info_from_signed_public_subkey)
            .collect::<Vec<_>>()
    }

    /// Verify the certificate's self-signatures and subkey binding signatures.
    fn verify_bindings(&self) -> PyResult<()> {
        self.inner.verify_bindings().map_err(to_py_err)
    }

    /// Serialize the transferable public key to binary packet bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    /// Serialize the transferable public key as ASCII armor.
    fn to_armored(&self) -> PyResult<String> {
        self.inner
            .to_armored_string(ArmorOptions::default())
            .map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "PublicKey(fingerprint='{}', key_id='{}')",
            self.fingerprint(),
            self.key_id()
        )
    }
}

/// A transferable OpenPGP secret key, including any secret subkeys.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct SecretKey {
    inner: SignedSecretKey,
}

#[pymethods]
impl SecretKey {
    /// Parse an ASCII-armored transferable secret key.
    #[staticmethod]
    fn from_armor(data: &str) -> PyResult<(Self, Headers)> {
        let (inner, headers) = SignedSecretKey::from_string(data).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    /// Parse a binary transferable secret key.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = SignedSecretKey::from_bytes(Cursor::new(data)).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// The RFC 9580 fingerprint of the primary key.
    #[getter]
    fn fingerprint(&self) -> String {
        self.inner
            .primary_key
            .public_key()
            .fingerprint()
            .to_string()
    }

    /// The legacy key identifier of the primary key.
    #[getter]
    fn key_id(&self) -> String {
        self.inner
            .primary_key
            .public_key()
            .legacy_key_id()
            .to_string()
    }

    /// The OpenPGP key-packet version number of the primary key.
    #[getter]
    fn version(&self) -> u8 {
        key_version_number(self.inner.primary_key.version())
    }

    /// The primary key packet's creation time as seconds since the Unix epoch.
    #[getter]
    fn created_at(&self) -> u32 {
        self.inner.primary_key.created_at().as_secs()
    }

    /// The primary key packet's public-key algorithm.
    #[getter]
    fn public_key_algorithm(&self) -> String {
        public_key_algorithm_name(self.inner.primary_key.algorithm()).to_string()
    }

    /// Structured algorithm-specific public-key metadata from `KeyDetails.public_params()`.
    #[getter]
    fn public_params(&self) -> PublicParamsInfo {
        public_params_info_from_params(self.inner.primary_key.public_params())
    }

    /// The RFC 9580 packet-header framing used by the primary secret-key packet.
    #[getter]
    fn packet_version(&self) -> PyPacketHeaderVersion {
        PyPacketHeaderVersion {
            inner: self.inner.primary_key.packet_header_version(),
        }
    }

    /// The number of public subkeys attached to the secret key.
    #[getter]
    fn public_subkey_count(&self) -> usize {
        self.inner.public_subkeys.len()
    }

    /// The number of secret subkeys attached to the secret key.
    #[getter]
    fn secret_subkey_count(&self) -> usize {
        self.inner.secret_subkeys.len()
    }

    /// UTF-8 decoded user IDs, with invalid octets replaced lossily.
    #[getter]
    fn user_ids(&self) -> Vec<String> {
        lossy_user_ids(&self.inner.details)
    }

    /// Return direct-key self-signature metadata attached to the secret certificate.
    ///
    /// RFC 9580 version-6 certificates place certificate-wide preferences, key flags, and
    /// feature advertisements on these direct-key signatures.
    fn direct_signature_infos(&self) -> Vec<SignatureInfo> {
        direct_signature_infos_from_details(&self.inner.details)
    }

    /// Return user IDs together with their certification self-signatures.
    ///
    /// Version-4 certificates carry certificate metadata such as key flags and preferred
    /// algorithms on the primary user-ID binding signature.
    fn user_bindings(&self) -> Vec<UserBindingInfo> {
        user_binding_infos_from_details(&self.inner.details)
    }

    /// Return user attributes together with their certification self-signatures.
    fn user_attribute_bindings(&self) -> Vec<UserAttributeBindingInfo> {
        user_attribute_binding_infos_from_details(&self.inner.details)
    }

    /// Return secret subkeys together with their binding-signature metadata.
    fn subkey_bindings(&self) -> Vec<SubkeyBindingInfo> {
        self.inner
            .secret_subkeys
            .iter()
            .map(subkey_binding_info_from_signed_secret_subkey)
            .collect::<Vec<_>>()
    }

    /// Return the primary secret key packet's RFC 9580 S2K protection parameters.
    ///
    /// Unprotected keys return an ``S2kParams`` instance with usage ``"unprotected"``.
    fn primary_secret_s2k(&self) -> PyS2kParams {
        s2k_params_from_secret_params(self.inner.primary_key.secret_params())
    }

    /// Return RFC 9580 S2K protection parameters for each secret subkey packet.
    fn secret_subkey_s2ks(&self) -> Vec<PyS2kParams> {
        self.inner
            .secret_subkeys
            .iter()
            .map(|subkey| s2k_params_from_secret_params(subkey.key.secret_params()))
            .collect()
    }

    /// Verify the secret key's self-signatures and subkey binding signatures.
    fn verify_bindings(&self) -> PyResult<()> {
        self.inner.verify_bindings().map_err(to_py_err)
    }

    /// Drop the secret key material and return the corresponding public certificate.
    fn to_public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.to_public_key(),
        }
    }

    /// Serialize the transferable secret key to binary packet bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    /// Serialize the transferable secret key as ASCII armor.
    fn to_armored(&self) -> PyResult<String> {
        self.inner
            .to_armored_string(ArmorOptions::default())
            .map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "SecretKey(fingerprint='{}', key_id='{}')",
            self.fingerprint(),
            self.key_id()
        )
    }
}

fn pkesk_version_number(version: pgp::types::PkeskVersion) -> u8 {
    match version {
        pgp::types::PkeskVersion::V3 => 3,
        pgp::types::PkeskVersion::V6 => 6,
        pgp::types::PkeskVersion::Other(value) => value,
    }
}

fn skesk_version_number(version: pgp::types::SkeskVersion) -> u8 {
    match version {
        pgp::types::SkeskVersion::V4 => 4,
        pgp::types::SkeskVersion::V5 => 5,
        pgp::types::SkeskVersion::V6 => 6,
        pgp::types::SkeskVersion::Other(value) => value,
    }
}

#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct PublicKeyEncryptedSessionKeyPacket {
    inner: PgpPublicKeyEncryptedSessionKey,
}

#[pymethods]
impl PublicKeyEncryptedSessionKeyPacket {
    #[getter]
    fn version(&self) -> u8 {
        pkesk_version_number(self.inner.version())
    }

    #[getter]
    fn public_key_algorithm(&self) -> Option<String> {
        self.inner
            .algorithm()
            .ok()
            .map(|algorithm| public_key_algorithm_name(algorithm).to_string())
    }

    #[getter]
    fn recipient_key_id(&self) -> Option<String> {
        self.inner
            .id()
            .ok()
            .filter(|key_id| !key_id.is_wildcard())
            .map(|key_id| key_id.to_string())
    }

    #[getter]
    fn recipient_fingerprint(&self) -> Option<String> {
        self.inner
            .fingerprint()
            .ok()
            .and_then(|fingerprint| fingerprint.map(|fingerprint| fingerprint.to_string()))
    }

    #[getter]
    fn recipient_is_anonymous(&self) -> bool {
        match self.inner.version() {
            pgp::types::PkeskVersion::V3 => self.inner.id().map(|key_id| key_id.is_wildcard()).unwrap_or(false),
            pgp::types::PkeskVersion::V6 => {
                self.inner.fingerprint().map(|fingerprint| fingerprint.is_none()).unwrap_or(false)
            }
            pgp::types::PkeskVersion::Other(_) => false,
        }
    }

    fn values_bytes(&self) -> PyResult<Option<Vec<u8>>> {
        match self.inner.values() {
            Ok(values) => serialize_packet_body(values).map(Some),
            Err(_) => Ok(None),
        }
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        serialize_packet_with_header(&self.inner)
    }

    fn __repr__(&self) -> String {
        format!(
            "PublicKeyEncryptedSessionKeyPacket(version={}, public_key_algorithm={:?})",
            self.version(),
            self.public_key_algorithm()
        )
    }
}

#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct SymKeyEncryptedSessionKeyPacket {
    inner: PgpSymKeyEncryptedSessionKey,
}

fn skesk_aead_algorithm(packet: &PgpSymKeyEncryptedSessionKey) -> Option<String> {
    match packet {
        PgpSymKeyEncryptedSessionKey::V5 { aead, .. }
        | PgpSymKeyEncryptedSessionKey::V6 { aead, .. } => {
            Some(normalized_algorithm_name(AeadAlgorithm::from(aead)))
        }
        _ => None,
    }
}

fn skesk_aead_iv(packet: &PgpSymKeyEncryptedSessionKey) -> Option<Vec<u8>> {
    match packet {
        PgpSymKeyEncryptedSessionKey::V5 { aead, .. }
        | PgpSymKeyEncryptedSessionKey::V6 { aead, .. } => Some(match aead {
            pgp::packet::AeadProps::Eax { iv } => iv.to_vec(),
            pgp::packet::AeadProps::Ocb { iv } => iv.to_vec(),
            pgp::packet::AeadProps::Gcm { iv } => iv.to_vec(),
        }),
        _ => None,
    }
}

#[pymethods]
impl SymKeyEncryptedSessionKeyPacket {
    #[getter]
    fn version(&self) -> u8 {
        skesk_version_number(self.inner.version())
    }

    #[getter]
    fn symmetric_algorithm(&self) -> Option<String> {
        self.inner
            .sym_algorithm()
            .map(|algorithm| normalized_algorithm_name(algorithm))
    }

    #[getter]
    fn aead_algorithm(&self) -> Option<String> {
        skesk_aead_algorithm(&self.inner)
    }

    #[getter]
    fn string_to_key(&self) -> Option<PyStringToKey> {
        self.inner
            .s2k()
            .map(|string_to_key| PyStringToKey {
                inner: string_to_key.clone(),
            })
    }

    #[getter]
    fn encrypted_key(&self) -> Option<Vec<u8>> {
        self.inner
            .encrypted_key()
            .map(|encrypted_key| encrypted_key.to_vec())
    }

    #[getter]
    fn aead_iv(&self) -> Option<Vec<u8>> {
        skesk_aead_iv(&self.inner)
    }

    #[getter]
    fn is_supported(&self) -> bool {
        self.inner.is_supported()
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        serialize_packet_with_header(&self.inner)
    }

    fn __repr__(&self) -> String {
        format!(
            "SymKeyEncryptedSessionKeyPacket(version={}, symmetric_algorithm={:?})",
            self.version(),
            self.symmetric_algorithm()
        )
    }
}

#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct EncryptedDataPacket {
    kind: String,
    version: Option<u8>,
    symmetric_algorithm: Option<String>,
    aead_algorithm: Option<String>,
    chunk_size: Option<u8>,
    salt: Option<Vec<u8>>,
    iv: Option<Vec<u8>>,
    data: Vec<u8>,
    packet_bytes: Vec<u8>,
}

fn encrypted_data_packet_from_packet(packet: PgpPacket) -> PyResult<EncryptedDataPacket> {
    match packet {
        PgpPacket::SymEncryptedData(packet) => Ok(EncryptedDataPacket {
            kind: "sed".to_string(),
            version: None,
            symmetric_algorithm: None,
            aead_algorithm: None,
            chunk_size: None,
            salt: None,
            iv: None,
            data: packet.data().to_vec(),
            packet_bytes: serialize_packet_with_header(&packet)?,
        }),
        PgpPacket::SymEncryptedProtectedData(packet) => {
            let packet_bytes = serialize_packet_with_header(&packet)?;
            let data = packet.data().to_vec();
            match packet.config() {
                PgpSymEncryptedProtectedDataConfig::V1 => Ok(EncryptedDataPacket {
                    kind: "seipd-v1".to_string(),
                    version: Some(1),
                    symmetric_algorithm: None,
                    aead_algorithm: None,
                    chunk_size: None,
                    salt: None,
                    iv: None,
                    data,
                    packet_bytes,
                }),
                PgpSymEncryptedProtectedDataConfig::V2 {
                    sym_alg,
                    aead,
                    chunk_size,
                    salt,
                } => Ok(EncryptedDataPacket {
                    kind: "seipd-v2".to_string(),
                    version: Some(2),
                    symmetric_algorithm: Some(normalized_algorithm_name(sym_alg)),
                    aead_algorithm: Some(normalized_algorithm_name(aead)),
                    chunk_size: Some((*chunk_size).into()),
                    salt: Some(salt.to_vec()),
                    iv: None,
                    data,
                    packet_bytes,
                }),
            }
        }
        PgpPacket::GnupgAeadData(packet) => {
            let packet_bytes = serialize_packet_with_header(&packet)?;
            let body = serialize_packet_body(&packet)?;
            if body.len() < 4 {
                return Err(to_py_err("invalid GnuPG AEAD packet body"));
            }
            let aead = AeadAlgorithm::from(body[2]);
            let iv_size = aead.iv_size();
            if body.len() < 4 + iv_size {
                return Err(to_py_err("invalid GnuPG AEAD packet body"));
            }

            Ok(EncryptedDataPacket {
                kind: "gnupg-aead".to_string(),
                version: Some(body[0]),
                symmetric_algorithm: Some(normalized_algorithm_name(SymmetricKeyAlgorithm::from(
                    body[1],
                ))),
                aead_algorithm: Some(normalized_algorithm_name(aead)),
                chunk_size: Some(body[3]),
                salt: None,
                iv: Some(body[4..4 + iv_size].to_vec()),
                data: body[4 + iv_size..].to_vec(),
                packet_bytes,
            })
        }
        _ => Err(to_py_err("expected an encrypted data packet")),
    }
}

fn top_level_encryption_packets_from_source(
    source: &[u8],
    headers: &Option<Headers>,
) -> PyResult<(
    Vec<PublicKeyEncryptedSessionKeyPacket>,
    Vec<SymKeyEncryptedSessionKeyPacket>,
    EncryptedDataPacket,
)> {
    let packets = parse_top_level_packets(source, headers)?;
    let mut public_key_packets = Vec::new();
    let mut symmetric_key_packets = Vec::new();
    let mut encrypted_data_packet = None;

    for packet in packets {
        match packet {
            PgpPacket::PublicKeyEncryptedSessionKey(packet) => {
                public_key_packets.push(PublicKeyEncryptedSessionKeyPacket { inner: packet });
            }
            PgpPacket::SymKeyEncryptedSessionKey(packet) => {
                symmetric_key_packets.push(SymKeyEncryptedSessionKeyPacket { inner: packet });
            }
            PgpPacket::SymEncryptedData(_)
            | PgpPacket::SymEncryptedProtectedData(_)
            | PgpPacket::GnupgAeadData(_) => {
                if encrypted_data_packet.is_some() {
                    return Err(to_py_err(
                        "message contains multiple encrypted data packets at the top level",
                    ));
                }
                encrypted_data_packet = Some(encrypted_data_packet_from_packet(packet)?);
            }
            PgpPacket::Marker(_) | PgpPacket::Padding(_) => {}
            _ => {
                return Err(to_py_err(
                    "message is not a top-level encrypted packet sequence",
                ));
            }
        }
    }

    let encrypted_data_packet = encrypted_data_packet
        .ok_or_else(|| to_py_err("message does not contain a top-level encrypted data packet"))?;
    Ok((public_key_packets, symmetric_key_packets, encrypted_data_packet))
}

fn plain_session_key_from_message_source(
    source: &[u8],
    headers: &Option<Headers>,
    session_key: &[u8],
    symmetric_algorithm: Option<&str>,
) -> PyResult<PgpPlainSessionKey> {
    let (_, _, encrypted_data_packet) = top_level_encryption_packets_from_source(source, headers)?;

    match encrypted_data_packet.kind.as_str() {
        "seipd-v1" => {
            let symmetric_algorithm = symmetric_algorithm
                .ok_or_else(|| {
                    to_py_err(
                        "symmetric_algorithm is required when decrypting a SEIPD v1 message with a raw session key",
                    )
                })
                .and_then(symmetric_algorithm_from_name)?;
            let key = raw_session_key_from_bytes(session_key, symmetric_algorithm)?;
            Ok(PgpPlainSessionKey::V3_4 {
                sym_alg: symmetric_algorithm,
                key,
            })
        }
        "seipd-v2" => {
            let expected_algorithm = encrypted_data_packet
                .symmetric_algorithm
                .as_deref()
                .ok_or_else(|| to_py_err("SEIPD v2 packet did not expose a symmetric algorithm"))
                .and_then(symmetric_algorithm_from_name)?;
            if let Some(provided_algorithm) = symmetric_algorithm {
                let provided_algorithm = symmetric_algorithm_from_name(provided_algorithm)?;
                if provided_algorithm != expected_algorithm {
                    return Err(to_py_err(
                        "symmetric_algorithm does not match the algorithm encoded in the SEIPD v2 packet",
                    ));
                }
            }
            let key = raw_session_key_from_bytes(session_key, expected_algorithm)?;
            Ok(PgpPlainSessionKey::V6 { key })
        }
        "sed" => Err(to_py_err(
            "legacy SymEncryptedData packets are not supported by decrypt_with_session_key",
        )),
        "gnupg-aead" => Err(to_py_err(
            "GnuPG AEAD packets are not supported by decrypt_with_session_key",
        )),
        _ => Err(to_py_err("message is not encrypted")),
    }
}

#[pymethods]
impl EncryptedDataPacket {
    #[getter]
    fn kind(&self) -> String {
        self.kind.clone()
    }

    #[getter]
    fn version(&self) -> Option<u8> {
        self.version
    }

    #[getter]
    fn symmetric_algorithm(&self) -> Option<String> {
        self.symmetric_algorithm.clone()
    }

    #[getter]
    fn aead_algorithm(&self) -> Option<String> {
        self.aead_algorithm.clone()
    }

    #[getter]
    fn chunk_size(&self) -> Option<u8> {
        self.chunk_size
    }

    #[getter]
    fn salt(&self) -> Option<Vec<u8>> {
        self.salt.clone()
    }

    #[getter]
    fn iv(&self) -> Option<Vec<u8>> {
        self.iv.clone()
    }

    fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.packet_bytes.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "EncryptedDataPacket(kind='{}', version={:?})",
            self.kind, self.version
        )
    }
}

/// A parsed OpenPGP message.
///
/// The message may be literal, compressed, signed, or encrypted.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct Message {
    source: Vec<u8>,
    info: MessageInfo,
}

fn owned_message_from_source(source: Vec<u8>) -> PyResult<Message> {
    let info = inspect_message_from_source(&source).map_err(to_py_err)?;
    Ok(Message { source, info })
}

fn decrypted_message_from_parsed(mut message: PgpMessage<'_>) -> PyResult<DecryptedMessage> {
    let (kind, is_nested, is_signed, is_compressed, is_literal) = match &message {
        PgpMessage::Literal { is_nested, .. } => ("literal", *is_nested, false, false, true),
        PgpMessage::Compressed { is_nested, .. } => ("compressed", *is_nested, false, true, false),
        PgpMessage::Signed { is_nested, .. } => ("signed", *is_nested, true, false, false),
        PgpMessage::Encrypted { .. } => {
            return Err(to_py_err("message is still encrypted after decryption"));
        }
    };

    while message.is_compressed() {
        message = message.decompress().map_err(to_py_err)?;
    }

    let literal_mode = message
        .literal_data_header()
        .map(|header| data_mode_name(header.mode()));
    let literal_filename = message
        .literal_data_header()
        .map(|header| header.file_name().to_vec());
    let payload = message.as_data_vec().map_err(to_py_err)?;
    let signatures = match &message {
        PgpMessage::Signed { reader, .. } => reader
            .signatures()
            .ok_or_else(|| to_py_err("cannot inspect signatures before reading the message"))?
            .iter()
            .map(decrypted_signature_from_full_signature)
            .collect(),
        _ => Vec::new(),
    };

    Ok(DecryptedMessage {
        kind: kind.to_string(),
        is_nested,
        is_signed,
        is_compressed,
        is_literal,
        payload,
        literal_mode,
        literal_filename,
        signatures,
    })
}

fn signature_infos_from_signed_message(
    mut message: PgpMessage<'_>,
) -> PyResult<Vec<SignatureInfo>> {
    message.as_data_vec().map_err(to_py_err)?;

    match &message {
        PgpMessage::Signed { reader, .. } => Ok(reader
            .signatures()
            .ok_or_else(|| to_py_err("cannot inspect signatures before reading the message"))?
            .iter()
            .map(signature_info_from_full_signature)
            .collect()),
        PgpMessage::Encrypted { .. } => Err(to_py_err(
            "message must be decrypted before inspecting signatures",
        )),
        _ => Ok(Vec::new()),
    }
}

fn verify_message_signature_info(
    mut message: PgpMessage<'_>,
    key: &SignedPublicKey,
    index: usize,
) -> PyResult<SignatureInfo> {
    message.as_data_vec().map_err(to_py_err)?;

    let info = match &message {
        PgpMessage::Signed { reader, .. } => {
            let signatures = reader
                .signatures()
                .ok_or_else(|| to_py_err("cannot verify signatures before reading the message"))?;
            let signature = signatures
                .get(index)
                .ok_or_else(|| to_py_err("signature index out of range"))?;
            signature_info_from_full_signature(signature)
        }
        PgpMessage::Encrypted { .. } => {
            return Err(to_py_err(
                "message must be decrypted before verifying signatures",
            ));
        }
        PgpMessage::Literal { .. } => {
            return Err(to_py_err("message was not signed"));
        }
        PgpMessage::Compressed { .. } => {
            return Err(to_py_err(
                "message must be decompressed before verifying signatures",
            ));
        }
    };

    message
        .verify_nested_explicit(index, key)
        .map_err(to_py_err)?;
    Ok(info)
}

#[pymethods]
impl Message {
    /// Parse an ASCII-armored OpenPGP message.
    #[staticmethod]
    fn from_armor(data: &str) -> PyResult<(Self, Headers)> {
        let info = inspect_message_from_source(data.as_bytes()).map_err(to_py_err)?;
        let headers = info.headers.clone().unwrap_or_default();
        Ok((
            Self {
                source: data.as_bytes().to_vec(),
                info,
            },
            headers,
        ))
    }

    /// Parse a binary OpenPGP message.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        owned_message_from_source(data.to_vec())
    }

    /// Return the message as binary OpenPGP packet bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        binary_message_source(&self.source, &self.info.headers)
    }

    /// The top-level message kind: literal, compressed, signed, or encrypted.
    #[getter]
    fn kind(&self) -> String {
        self.info.kind.clone()
    }

    /// Whether this message was nested inside another OpenPGP message layer.
    #[getter]
    fn is_nested(&self) -> bool {
        self.info.is_nested
    }

    /// ASCII-armor headers if the message was parsed from armor.
    #[getter]
    fn headers(&self) -> Option<Headers> {
        self.info.headers.clone()
    }

    /// Whether the top-level message is signed.
    #[getter]
    fn is_signed(&self) -> bool {
        self.kind() == "signed"
    }

    /// Whether the top-level message is compressed.
    #[getter]
    fn is_compressed(&self) -> bool {
        self.kind() == "compressed"
    }

    /// Whether the top-level message is literal data.
    #[getter]
    fn is_literal(&self) -> bool {
        self.kind() == "literal"
    }

    /// Read the inner payload as bytes, automatically decompressing nested compressed layers.
    fn payload_bytes(&self) -> PyResult<Vec<u8>> {
        payload_bytes_from_source(&self.source)
    }

    /// Read the inner payload as UTF-8 text, automatically decompressing nested compressed layers.
    fn payload_text(&self) -> PyResult<String> {
        payload_text_from_source(&self.source)
    }

    /// Return the literal data mode after automatic decompression, if a literal layer exists.
    fn literal_mode(&self) -> PyResult<Option<String>> {
        literal_mode_from_source(&self.source)
    }

    /// Return the literal file name octets after automatic decompression, if available.
    fn literal_filename(&self) -> PyResult<Option<Vec<u8>>> {
        literal_filename_from_source(&self.source)
    }

    /// Return the number of signatures after automatic decompression.
    ///
    /// For signed messages this includes both one-pass and prefixed signatures.
    fn signature_count(&self) -> PyResult<usize> {
        signature_count_from_source(&self.source)
    }

    /// Return the number of one-pass signatures after automatic decompression.
    fn one_pass_signature_count(&self) -> PyResult<usize> {
        one_pass_signature_count_from_source(&self.source)
    }

    /// Return the number of prefixed (non-one-pass) signatures after automatic decompression.
    fn regular_signature_count(&self) -> PyResult<usize> {
        regular_signature_count_from_source(&self.source)
    }

    /// Return metadata for each signature packet on a signed message.
    ///
    /// This reads the message to the end to finalize one-pass signature verification state,
    /// mirroring the requirements of RFC 9580 one-pass signatures.
    fn signature_infos(&self) -> PyResult<Vec<SignatureInfo>> {
        signature_infos_from_source(&self.source)
    }

    /// Return the top-level public-key encrypted session key packets on an encrypted message.
    fn public_key_encrypted_session_key_packets(
        &self,
    ) -> PyResult<Vec<PublicKeyEncryptedSessionKeyPacket>> {
        let (public_key_packets, _, _) =
            top_level_encryption_packets_from_source(&self.source, &self.info.headers)?;
        Ok(public_key_packets)
    }

    /// Return the top-level password-encrypted session key packets on an encrypted message.
    fn symmetric_key_encrypted_session_key_packets(
        &self,
    ) -> PyResult<Vec<SymKeyEncryptedSessionKeyPacket>> {
        let (_, symmetric_key_packets, _) =
            top_level_encryption_packets_from_source(&self.source, &self.info.headers)?;
        Ok(symmetric_key_packets)
    }

    /// Return the top-level encrypted data packet on an encrypted message.
    fn encrypted_data_packet(&self) -> PyResult<EncryptedDataPacket> {
        let (_, _, encrypted_data_packet) =
            top_level_encryption_packets_from_source(&self.source, &self.info.headers)?;
        Ok(encrypted_data_packet)
    }

    /// Verify a specific signature on the message and return its metadata.
    ///
    /// The default index of ``0`` corresponds to the first signature reported by
    /// :meth:`signature_infos`.
    #[pyo3(signature = (key, index=0))]
    fn verify_signature(&self, key: PyRef<'_, PublicKey>, index: usize) -> PyResult<SignatureInfo> {
        verify_signature_from_source(&self.source, &key.inner, index)
    }

    /// Verify a signed message against a public key.
    ///
    /// By default, this verifies the first signature on the message. Pass ``index`` to target a
    /// later signature in a multi-signed message.
    #[pyo3(signature = (key, index=0))]
    fn verify(&self, key: PyRef<'_, PublicKey>, index: usize) -> PyResult<()> {
        let _ = self.verify_signature(key, index)?;
        Ok(())
    }

    /// Decrypt an encrypted message using a secret key and optional key-protection password.
    ///
    /// The returned :class:`DecryptedMessage` preserves signature-inspection and verification
    /// helpers so encrypted-and-signed messages can still be verified after decryption.
    #[pyo3(signature = (key, password=None))]
    fn decrypt(
        &self,
        key: PyRef<'_, SecretKey>,
        password: Option<&str>,
    ) -> PyResult<DecryptedMessage> {
        let key_password = password_from_option(password);
        let (message, _) = parse_message(&self.source).map_err(to_py_err)?;
        let decrypted = message
            .decrypt(&key_password, &key.inner)
            .map_err(to_py_err)?;
        decrypted_message_from_parsed(decrypted)
    }

    /// Decrypt an encrypted message using a message password.
    ///
    /// The returned :class:`DecryptedMessage` preserves signature-inspection helpers for any
    /// signed payload revealed by decryption.
    fn decrypt_with_password(&self, password: &str) -> PyResult<DecryptedMessage> {
        let message_password = Password::from(password);
        let (message, _) = parse_message(&self.source).map_err(to_py_err)?;
        let decrypted = message
            .decrypt_with_password(&message_password)
            .map_err(to_py_err)?;
        decrypted_message_from_parsed(decrypted)
    }

    /// Decrypt an encrypted message with a raw session key.
    ///
    /// For SEIPD v1 messages, ``symmetric_algorithm`` is required because the encrypted data packet
    /// does not encode the algorithm. For SEIPD v2 messages the algorithm is inferred from the
    /// packet and any provided value must match.
    #[pyo3(signature = (session_key, symmetric_algorithm=None))]
    fn decrypt_with_session_key(
        &self,
        session_key: &[u8],
        symmetric_algorithm: Option<&str>,
    ) -> PyResult<DecryptedMessage> {
        let plain_session_key = plain_session_key_from_message_source(
            &self.source,
            &self.info.headers,
            session_key,
            symmetric_algorithm,
        )?;
        let (message, _) = parse_message(&self.source).map_err(to_py_err)?;
        let decrypted = message
            .decrypt_with_session_key(plain_session_key)
            .map_err(to_py_err)?;
        decrypted_message_from_parsed(decrypted)
    }

    fn __repr__(&self) -> String {
        format!(
            "Message(kind='{}', is_nested={})",
            self.info.kind, self.info.is_nested
        )
    }
}

/// A decrypted OpenPGP message with eagerly extracted payload, metadata, and signatures.
///
/// The decrypted payload is materialized once so Python code can continue inspecting or verifying
/// signed content that was revealed by decryption.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct DecryptedMessage {
    kind: String,
    is_nested: bool,
    is_signed: bool,
    is_compressed: bool,
    is_literal: bool,
    payload: Vec<u8>,
    literal_mode: Option<String>,
    literal_filename: Option<Vec<u8>>,
    signatures: Vec<DecryptedSignature>,
}

#[pymethods]
impl DecryptedMessage {
    /// The top-level decrypted message kind.
    #[getter]
    fn kind(&self) -> String {
        self.kind.clone()
    }

    /// Whether the decrypted message was nested inside another message layer.
    #[getter]
    fn is_nested(&self) -> bool {
        self.is_nested
    }

    /// Whether the decrypted top-level message is signed.
    #[getter]
    fn is_signed(&self) -> bool {
        self.is_signed
    }

    /// Whether the decrypted top-level message is compressed.
    #[getter]
    fn is_compressed(&self) -> bool {
        self.is_compressed
    }

    /// Whether the decrypted top-level message is literal data.
    #[getter]
    fn is_literal(&self) -> bool {
        self.is_literal
    }

    /// The decrypted payload bytes after automatic decompression.
    fn payload_bytes(&self) -> Vec<u8> {
        self.payload.clone()
    }

    /// The decrypted payload as UTF-8 text.
    fn payload_text(&self) -> PyResult<String> {
        String::from_utf8(self.payload.clone()).map_err(to_py_err)
    }

    /// The literal data mode after automatic decompression, if a literal layer exists.
    fn literal_mode(&self) -> Option<String> {
        self.literal_mode.clone()
    }

    /// The literal file name octets after automatic decompression, if available.
    fn literal_filename(&self) -> Option<Vec<u8>> {
        self.literal_filename.clone()
    }

    /// Return the number of signatures revealed by decryption and automatic decompression.
    fn signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Return the number of one-pass signatures revealed by decryption.
    fn one_pass_signature_count(&self) -> usize {
        self.signatures
            .iter()
            .filter(|signature| signature.is_one_pass)
            .count()
    }

    /// Return the number of prefixed (non-one-pass) signatures revealed by decryption.
    fn regular_signature_count(&self) -> usize {
        self.signatures
            .iter()
            .filter(|signature| !signature.is_one_pass)
            .count()
    }

    /// Return metadata for every signature packet revealed by decryption.
    fn signature_infos(&self) -> Vec<SignatureInfo> {
        self.signatures
            .iter()
            .map(signature_info_from_decrypted_signature)
            .collect()
    }

    /// Verify a specific signature on the decrypted payload and return its metadata.
    ///
    /// The default index of ``0`` corresponds to the first signature reported by
    /// :meth:`signature_infos`.
    #[pyo3(signature = (key, index=0))]
    fn verify_signature(&self, key: PyRef<'_, PublicKey>, index: usize) -> PyResult<SignatureInfo> {
        if self.signatures.is_empty() {
            return Err(to_py_err("message was not signed"));
        }

        let signature = self
            .signatures
            .get(index)
            .ok_or_else(|| to_py_err("signature index out of range"))?;
        signature
            .signature
            .verify(&key.inner, Cursor::new(self.payload.as_slice()))
            .map_err(to_py_err)?;
        Ok(signature_info_from_decrypted_signature(signature))
    }

    /// Verify a signed decrypted payload against a public key.
    ///
    /// By default, this verifies the first signature on the decrypted payload. Pass ``index`` to
    /// target a later signature in a multi-signed payload.
    #[pyo3(signature = (key, index=0))]
    fn verify(&self, key: PyRef<'_, PublicKey>, index: usize) -> PyResult<()> {
        let _ = self.verify_signature(key, index)?;
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!(
            "DecryptedMessage(kind='{}', is_nested={})",
            self.kind, self.is_nested
        )
    }
}

/// Decoded RFC 9580 key-flags subpacket metadata.
#[pyclass(module = "openpgp")]
#[derive(Clone, Copy)]
struct KeyFlagsInfo {
    certify: bool,
    sign: bool,
    encrypt_communications: bool,
    encrypt_storage: bool,
    authenticate: bool,
    shared: bool,
    draft_decrypt_forwarded: bool,
    group: bool,
    adsk: bool,
    timestamping: bool,
}

#[pymethods]
impl KeyFlagsInfo {
    /// Whether the key may certify other keys and user IDs.
    #[getter]
    fn certify(&self) -> bool {
        self.certify
    }

    /// Whether the key may create data signatures.
    #[getter]
    fn sign(&self) -> bool {
        self.sign
    }

    /// Whether the key may encrypt communications.
    #[getter]
    fn encrypt_communications(&self) -> bool {
        self.encrypt_communications
    }

    /// Whether the key may encrypt storage.
    #[getter]
    fn encrypt_storage(&self) -> bool {
        self.encrypt_storage
    }

    /// Whether the key may be used for authentication.
    #[getter]
    fn authenticate(&self) -> bool {
        self.authenticate
    }

    /// Whether the key is marked as split or shared between multiple holders.
    #[getter]
    fn shared(&self) -> bool {
        self.shared
    }

    /// Whether the draft forwarded-decryption key-flag bit is set.
    #[getter]
    fn draft_decrypt_forwarded(&self) -> bool {
        self.draft_decrypt_forwarded
    }

    /// Whether the key belongs to a group key-management arrangement.
    #[getter]
    fn group(&self) -> bool {
        self.group
    }

    /// Whether the key is marked for additional decryption subkeys (ADSK).
    #[getter]
    fn adsk(&self) -> bool {
        self.adsk
    }

    /// Whether the key may create trusted timestamps.
    #[getter]
    fn timestamping(&self) -> bool {
        self.timestamping
    }

    fn __repr__(&self) -> String {
        format!(
            "KeyFlagsInfo(certify={}, sign={}, encrypt_communications={}, encrypt_storage={}, authenticate={})",
            self.certify,
            self.sign,
            self.encrypt_communications,
            self.encrypt_storage,
            self.authenticate,
        )
    }
}

#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct UserAttribute {
    inner: PgpUserAttribute,
}

#[pymethods]
impl UserAttribute {
    /// Create an RFC 9580 image user attribute with the standard JPEG header framing.
    #[staticmethod]
    fn image_jpeg(data: &[u8]) -> PyResult<Self> {
        let inner = PgpUserAttribute::new_image(data.to_vec().into()).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// The normalized RFC 9580 user-attribute type name.
    #[getter]
    fn kind(&self) -> String {
        user_attribute_kind_name(&self.inner).to_string()
    }

    /// The raw user-attribute payload bytes.
    #[getter]
    fn data(&self) -> Vec<u8> {
        user_attribute_data(&self.inner)
    }

    /// The image-header version for image attributes, if present.
    #[getter]
    fn image_header_version(&self) -> Option<u8> {
        user_attribute_image_header_version(&self.inner)
    }

    /// The normalized image format for image attributes, if present.
    #[getter]
    fn image_format(&self) -> Option<String> {
        user_attribute_image_format(&self.inner)
    }

    fn __repr__(&self) -> String {
        format!(
            "UserAttribute(kind='{}', data_len={})",
            self.kind(),
            self.data().len()
        )
    }
}

/// A signed user attribute and its attached certification self-signatures.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct UserAttributeBindingInfo {
    user_attribute: UserAttribute,
    signatures: Vec<SignatureInfo>,
}

#[pymethods]
impl UserAttributeBindingInfo {
    /// The underlying user-attribute packet metadata.
    #[getter]
    fn user_attribute(&self) -> UserAttribute {
        self.user_attribute.clone()
    }

    /// Metadata for every certification signature attached to this user attribute.
    #[getter]
    fn signatures(&self) -> Vec<SignatureInfo> {
        self.signatures.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "UserAttributeBindingInfo(kind='{}', signature_count={})",
            self.user_attribute.kind(),
            self.signatures.len()
        )
    }
}

/// Decoded RFC 9580 Features subpacket metadata.
#[pyclass(module = "openpgp")]
#[derive(Clone, Copy)]
struct FeaturesInfo {
    seipd_v1: bool,
    seipd_v2: bool,
}

#[pymethods]
impl FeaturesInfo {
    /// Whether the issuer advertises support for SEIPD v1 packets.
    #[getter]
    fn seipd_v1(&self) -> bool {
        self.seipd_v1
    }

    /// Whether the issuer advertises support for SEIPD v2 packets.
    #[getter]
    fn seipd_v2(&self) -> bool {
        self.seipd_v2
    }

    fn __repr__(&self) -> String {
        format!(
            "FeaturesInfo(seipd_v1={}, seipd_v2={})",
            self.seipd_v1, self.seipd_v2
        )
    }
}

/// Structured `KeyDetails.public_params()` metadata for a key packet.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct PublicParamsInfo {
    kind: String,
    curve: Option<String>,
    curve_oid: Option<String>,
    curve_alias: Option<String>,
    curve_bits: Option<u16>,
    secret_key_length: Option<usize>,
    is_supported: Option<bool>,
    kdf_hash_algorithm: Option<String>,
    kdf_symmetric_algorithm: Option<String>,
    kdf_type: Option<String>,
}

#[pymethods]
impl PublicParamsInfo {
    /// The normalized `PublicParams` variant name.
    #[getter]
    fn kind(&self) -> String {
        self.kind.clone()
    }

    /// The normalized ECC curve name, when this key uses an elliptic-curve algorithm.
    #[getter]
    fn curve(&self) -> Option<String> {
        self.curve.clone()
    }

    /// The IETF OID string for elliptic-curve based keys, when available.
    #[getter]
    fn curve_oid(&self) -> Option<String> {
        self.curve_oid.clone()
    }

    /// The alternate curve alias exposed by rPGP, when available.
    #[getter]
    fn curve_alias(&self) -> Option<String> {
        self.curve_alias.clone()
    }

    /// The nominal elliptic-curve size in bits, when available.
    #[getter]
    fn curve_bits(&self) -> Option<u16> {
        self.curve_bits
    }

    /// The expected secret-key length in bytes for supported ECC algorithms, when available.
    #[getter]
    fn secret_key_length(&self) -> Option<usize> {
        self.secret_key_length
    }

    /// Whether rPGP recognizes and parses the curve-specific key material.
    #[getter]
    fn is_supported(&self) -> Option<bool> {
        self.is_supported
    }

    /// The ECDH KDF hash algorithm, when encoded in the public parameters.
    #[getter]
    fn kdf_hash_algorithm(&self) -> Option<String> {
        self.kdf_hash_algorithm.clone()
    }

    /// The ECDH KDF symmetric algorithm, when encoded in the public parameters.
    #[getter]
    fn kdf_symmetric_algorithm(&self) -> Option<String> {
        self.kdf_symmetric_algorithm.clone()
    }

    /// The ECDH KDF flavor for Curve25519 packets, when encoded.
    #[getter]
    fn kdf_type(&self) -> Option<String> {
        self.kdf_type.clone()
    }

    fn __repr__(&self) -> String {
        match &self.curve {
            Some(curve) => format!("PublicParamsInfo(kind='{}', curve='{}')", self.kind, curve),
            None => format!("PublicParamsInfo(kind='{}')", self.kind),
        }
    }
}

/// A subkey and its attached binding or revocation signatures.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct SubkeyBindingInfo {
    fingerprint: String,
    key_id: String,
    version: u8,
    created_at: u32,
    public_key_algorithm: String,
    public_params: PublicParamsInfo,
    packet_version: PgpPacketHeaderVersion,
    signatures: Vec<SignatureInfo>,
}

#[pymethods]
impl SubkeyBindingInfo {
    /// The RFC 9580 fingerprint of the subkey packet.
    #[getter]
    fn fingerprint(&self) -> String {
        self.fingerprint.clone()
    }

    /// The legacy key identifier of the subkey packet.
    #[getter]
    fn key_id(&self) -> String {
        self.key_id.clone()
    }

    /// The OpenPGP key-packet version number of this subkey.
    #[getter]
    fn version(&self) -> u8 {
        self.version
    }

    /// The subkey packet's creation time as seconds since the Unix epoch.
    #[getter]
    fn created_at(&self) -> u32 {
        self.created_at
    }

    /// The subkey packet's public-key algorithm.
    #[getter]
    fn public_key_algorithm(&self) -> String {
        self.public_key_algorithm.clone()
    }

    /// Structured algorithm-specific public-key metadata from `KeyDetails.public_params()`.
    #[getter]
    fn public_params(&self) -> PublicParamsInfo {
        self.public_params.clone()
    }

    /// The RFC 9580 packet-header framing used by this subkey packet.
    #[getter]
    fn packet_version(&self) -> PyPacketHeaderVersion {
        PyPacketHeaderVersion {
            inner: self.packet_version,
        }
    }

    /// Metadata for every binding or revocation signature attached to this subkey.
    #[getter]
    fn signatures(&self) -> Vec<SignatureInfo> {
        self.signatures.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "SubkeyBindingInfo(fingerprint='{}', key_id='{}', packet_version='{}', signature_count={})",
            self.fingerprint,
            self.key_id,
            packet_header_version_name(self.packet_version),
            self.signatures.len()
        )
    }
}

/// A user ID and its attached certification self-signatures.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct UserBindingInfo {
    user_id: String,
    is_primary: bool,
    signatures: Vec<SignatureInfo>,
}

#[pymethods]
impl UserBindingInfo {
    /// The user ID bytes decoded lossily as UTF-8.
    #[getter]
    fn user_id(&self) -> String {
        self.user_id.clone()
    }

    /// Whether any attached certification marks this as the primary user ID.
    #[getter]
    fn is_primary(&self) -> bool {
        self.is_primary
    }

    /// Metadata for every certification signature attached to this user ID.
    #[getter]
    fn signatures(&self) -> Vec<SignatureInfo> {
        self.signatures.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "UserBindingInfo(user_id={:?}, is_primary={}, signature_count={})",
            self.user_id,
            self.is_primary,
            self.signatures.len()
        )
    }
}

/// Metadata extracted from an OpenPGP data signature packet.
///
/// The fields mirror the RFC 9580 signature packet configuration, including issuer subpackets,
/// the 16-bit signed hash prefix, version-6 salts, and certificate self-signature metadata such
/// as key flags, features, and preferred algorithm lists when present.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct SignatureInfo {
    version: u8,
    signature_type: Option<String>,
    hash_algorithm: Option<String>,
    public_key_algorithm: Option<String>,
    issuer_key_ids: Vec<String>,
    issuer_fingerprints: Vec<String>,
    creation_time: Option<u32>,
    signature_expiration_seconds: Option<u32>,
    signer_user_id: Option<String>,
    signed_hash_value: Option<Vec<u8>>,
    salt: Option<Vec<u8>>,
    preferred_symmetric_algorithms: Vec<String>,
    preferred_hash_algorithms: Vec<String>,
    preferred_compression_algorithms: Vec<String>,
    preferred_aead_algorithms: Vec<(String, String)>,
    key_flags: KeyFlagsInfo,
    features: Option<FeaturesInfo>,
    embedded_signature: Option<Box<SignatureInfo>>,
    is_one_pass: bool,
}

#[pymethods]
impl SignatureInfo {
    /// The signature packet version number.
    #[getter]
    fn version(&self) -> u8 {
        self.version
    }

    /// The RFC 9580 signature type name, if this packet used a known signature format.
    #[getter]
    fn signature_type(&self) -> Option<String> {
        self.signature_type.clone()
    }

    /// The declared hash algorithm name, if this packet used a known signature format.
    #[getter]
    fn hash_algorithm(&self) -> Option<String> {
        self.hash_algorithm.clone()
    }

    /// The declared public-key algorithm name, if this packet used a known signature format.
    #[getter]
    fn public_key_algorithm(&self) -> Option<String> {
        self.public_key_algorithm.clone()
    }

    /// Any issuer key IDs from issuer-related subpackets.
    #[getter]
    fn issuer_key_ids(&self) -> Vec<String> {
        self.issuer_key_ids.clone()
    }

    /// Any issuer fingerprints from issuer fingerprint subpackets.
    #[getter]
    fn issuer_fingerprints(&self) -> Vec<String> {
        self.issuer_fingerprints.clone()
    }

    /// The signature creation time as seconds since the Unix epoch, if present.
    #[getter]
    fn creation_time(&self) -> Option<u32> {
        self.creation_time
    }

    /// The signature expiration interval in seconds, if present.
    #[getter]
    fn signature_expiration_seconds(&self) -> Option<u32> {
        self.signature_expiration_seconds
    }

    /// The signer's declared user ID from hashed subpackets, lossily decoded as UTF-8.
    #[getter]
    fn signer_user_id(&self) -> Option<String> {
        self.signer_user_id.clone()
    }

    /// The two-octet signed hash prefix stored in the signature packet, if available.
    #[getter]
    fn signed_hash_value(&self) -> Option<Vec<u8>> {
        self.signed_hash_value.clone()
    }

    /// The RFC 9580 version-6 signature salt, if this is a version-6 signature.
    #[getter]
    fn salt(&self) -> Option<Vec<u8>> {
        self.salt.clone()
    }

    /// Preferred symmetric algorithms advertised by this signature, normalized to lower-case.
    #[getter]
    fn preferred_symmetric_algorithms(&self) -> Vec<String> {
        self.preferred_symmetric_algorithms.clone()
    }

    /// Preferred hash algorithms advertised by this signature, normalized to lower-case.
    #[getter]
    fn preferred_hash_algorithms(&self) -> Vec<String> {
        self.preferred_hash_algorithms.clone()
    }

    /// Preferred compression algorithms advertised by this signature, normalized to lower-case.
    #[getter]
    fn preferred_compression_algorithms(&self) -> Vec<String> {
        self.preferred_compression_algorithms.clone()
    }

    /// Preferred AEAD algorithm pairs advertised by this signature, normalized to lower-case.
    #[getter]
    fn preferred_aead_algorithms(&self) -> Vec<(String, String)> {
        self.preferred_aead_algorithms.clone()
    }

    /// Decoded RFC 9580 key-flag bits advertised by this signature.
    #[getter]
    fn key_flags(&self) -> KeyFlagsInfo {
        self.key_flags
    }

    /// Decoded RFC 9580 feature-advertisement bits, if the signature carries them.
    #[getter]
    fn features(&self) -> Option<FeaturesInfo> {
        self.features
    }

    /// An embedded signature, such as the primary-key binding on a signing-capable subkey.
    #[getter]
    fn embedded_signature(&self) -> Option<SignatureInfo> {
        self.embedded_signature.as_deref().cloned()
    }

    /// Whether the signature originated from a one-pass signature packet.
    #[getter]
    fn is_one_pass(&self) -> bool {
        self.is_one_pass
    }

    fn __repr__(&self) -> String {
        format!(
            "SignatureInfo(version={}, signature_type={:?}, hash_algorithm={:?}, is_one_pass={})",
            self.version, self.signature_type, self.hash_algorithm, self.is_one_pass
        )
    }
}

/// A detached OpenPGP signature packet sequence.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct DetachedSignature {
    inner: PgpDetachedSignature,
}

#[pymethods]
impl DetachedSignature {
    /// Parse an ASCII-armored detached signature.
    #[staticmethod]
    fn from_armor(data: &str) -> PyResult<(Self, Headers)> {
        let (inner, headers) = PgpDetachedSignature::from_string(data).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    /// Parse a binary detached signature.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = PgpDetachedSignature::from_bytes(Cursor::new(data)).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Create a detached binary signature using SHA-256.
    #[staticmethod]
    #[pyo3(signature = (data, key, password=None))]
    fn sign_binary(
        data: &[u8],
        key: PyRef<'_, SecretKey>,
        password: Option<&str>,
    ) -> PyResult<Self> {
        let password = password_from_option(password);
        let inner = PgpDetachedSignature::sign_binary_data(
            rand::thread_rng(),
            &key.inner.primary_key,
            &password,
            HashAlgorithm::Sha256,
            Cursor::new(data),
        )
        .map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// Return metadata for the detached signature packet.
    fn signature_info(&self) -> SignatureInfo {
        signature_info_from_signature(&self.inner.signature, false)
    }

    /// Verify a detached signature against a public key and payload.
    fn verify(&self, key: PyRef<'_, PublicKey>, data: &[u8]) -> PyResult<()> {
        self.inner.verify(&key.inner, data).map_err(to_py_err)
    }

    /// Verify a detached signature and return its metadata.
    fn verify_signature(&self, key: PyRef<'_, PublicKey>, data: &[u8]) -> PyResult<SignatureInfo> {
        self.inner.verify(&key.inner, data).map_err(to_py_err)?;
        Ok(self.signature_info())
    }

    /// Serialize the detached signature to binary packet bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    /// Serialize the detached signature as ASCII armor.
    fn to_armored(&self) -> PyResult<String> {
        self.inner
            .to_armored_string(ArmorOptions::default())
            .map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        "DetachedSignature()".to_string()
    }
}

/// A cleartext signed message, following RFC 9580 section 7.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct CleartextSignedMessage {
    inner: PgpCleartextSignedMessage,
}

#[pymethods]
impl CleartextSignedMessage {
    /// Parse an ASCII-armored cleartext signed message.
    #[staticmethod]
    fn from_armor(data: &str) -> PyResult<(Self, Headers)> {
        let (inner, headers) = PgpCleartextSignedMessage::from_string(data).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    /// Create a cleartext signed message using SHA-256 text signatures.
    #[staticmethod]
    #[pyo3(signature = (text, key, password=None))]
    fn sign(text: &str, key: PyRef<'_, SecretKey>, password: Option<&str>) -> PyResult<Self> {
        let password = password_from_option(password);
        let inner =
            PgpCleartextSignedMessage::sign(rand::thread_rng(), text, &*key.inner, &password)
                .map_err(to_py_err)?;
        Ok(Self { inner })
    }

    /// The dash-escaped cleartext body exactly as serialized inside the framework.
    #[getter]
    fn text(&self) -> String {
        self.inner.text().to_string()
    }

    /// The normalized text that is hashed and verified, using CRLF line endings.
    fn signed_text(&self) -> String {
        self.inner.signed_text()
    }

    /// Return the number of signatures attached to the cleartext framework.
    fn signature_count(&self) -> usize {
        self.inner.signatures().len()
    }

    /// Return metadata for every cleartext signature packet.
    fn signature_infos(&self) -> Vec<SignatureInfo> {
        self.inner
            .signatures()
            .iter()
            .map(|signature| signature_info_from_signature(signature, false))
            .collect()
    }

    /// Verify at least one cleartext signature against the given public key and return metadata.
    ///
    /// If ``index`` is provided, only that signature packet is verified.
    #[pyo3(signature = (key, index=None))]
    fn verify_signature(
        &self,
        key: PyRef<'_, PublicKey>,
        index: Option<usize>,
    ) -> PyResult<SignatureInfo> {
        let signed_text = self.inner.signed_text();
        let signatures = self.inner.signatures();

        if let Some(index) = index {
            let signature = signatures
                .get(index)
                .ok_or_else(|| to_py_err("signature index out of range"))?;
            signature
                .verify(&key.inner, signed_text.as_bytes())
                .map_err(to_py_err)?;
            return Ok(signature_info_from_signature(signature, false));
        }

        for signature in signatures {
            if signature.verify(&key.inner, signed_text.as_bytes()).is_ok() {
                return Ok(signature_info_from_signature(signature, false));
            }
        }

        Err(to_py_err("no matching signature found"))
    }

    /// Verify at least one cleartext signature against the given public key.
    ///
    /// If ``index`` is provided, only that signature packet is verified.
    #[pyo3(signature = (key, index=None))]
    fn verify(&self, key: PyRef<'_, PublicKey>, index: Option<usize>) -> PyResult<()> {
        let _ = self.verify_signature(key, index)?;
        Ok(())
    }

    /// Serialize the cleartext signed message as ASCII armor.
    fn to_armored(&self) -> PyResult<String> {
        self.inner
            .to_armored_string(ArmorOptions::default())
            .map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        format!(
            "CleartextSignedMessage(signature_count={})",
            self.inner.signatures().len()
        )
    }
}

/// Lightweight metadata about an OpenPGP message.
#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct MessageInfo {
    kind: String,
    is_nested: bool,
    headers: Option<Headers>,
}

#[pymethods]
impl MessageInfo {
    /// The top-level message kind: literal, compressed, signed, or encrypted.
    #[getter]
    fn kind(&self) -> String {
        self.kind.clone()
    }

    /// Whether this message was nested inside another message layer.
    #[getter]
    fn is_nested(&self) -> bool {
        self.is_nested
    }

    /// ASCII-armor headers if the message was parsed from armor.
    #[getter]
    fn headers(&self) -> Option<Headers> {
        self.headers.clone()
    }

    fn __repr__(&self) -> String {
        format!(
            "MessageInfo(kind='{}', is_nested={})",
            self.kind, self.is_nested
        )
    }
}

/// Inspect an ASCII-armored or binary OpenPGP message without exposing its payload.
#[pyfunction]
fn inspect_message(data: &str) -> PyResult<MessageInfo> {
    parse_message_info_from_reader(Cursor::new(data.as_bytes())).map_err(to_py_err)
}

/// Inspect a binary OpenPGP message without exposing its payload.
#[pyfunction]
fn inspect_message_bytes(data: &[u8]) -> PyResult<MessageInfo> {
    parse_message_info_from_reader(Cursor::new(data)).map_err(to_py_err)
}

/// Create a simple binary signed message and return it as ASCII armor.
#[pyfunction]
#[pyo3(signature = (data, signer, password=None, file_name=""))]
fn sign_message(
    data: &[u8],
    signer: PyRef<'_, SecretKey>,
    password: Option<&str>,
    file_name: &str,
) -> PyResult<String> {
    let password = password_from_option(password);
    let mut builder =
        MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()));
    builder.sign(&signer.inner.primary_key, password, HashAlgorithm::Sha256);
    builder
        .to_armored_string(&mut rand::thread_rng(), ArmorOptions::default())
        .map_err(to_py_err)
}

/// Create a cleartext signed message and return it as ASCII armor.
#[pyfunction]
#[pyo3(signature = (text, signer, password=None))]
fn sign_cleartext_message(
    text: &str,
    signer: PyRef<'_, SecretKey>,
    password: Option<&str>,
) -> PyResult<String> {
    let password = password_from_option(password);
    let message =
        PgpCleartextSignedMessage::sign(rand::thread_rng(), text, &*signer.inner, &password)
            .map_err(to_py_err)?;
    message
        .to_armored_string(ArmorOptions::default())
        .map_err(to_py_err)
}

fn encrypt_session_key_to_recipient_inner(
    session_key: &[u8],
    recipient: &SignedPublicKey,
    version: EncryptionVersion,
    symmetric_algorithm: SymmetricKeyAlgorithm,
) -> PyResult<PgpPublicKeyEncryptedSessionKey> {
    let session_key = raw_session_key_from_bytes(session_key, symmetric_algorithm)?;
    if let Some(subkey) = recipient
        .public_subkeys
        .iter()
        .find(|subkey| subkey.algorithm().can_encrypt())
    {
        match version {
            EncryptionVersion::SeipdV1 => PgpPublicKeyEncryptedSessionKey::from_session_key_v3(
                rand::thread_rng(),
                &session_key,
                symmetric_algorithm,
                subkey,
            )
            .map_err(to_py_err),
            EncryptionVersion::SeipdV2 => PgpPublicKeyEncryptedSessionKey::from_session_key_v6(
                rand::thread_rng(),
                &session_key,
                subkey,
            )
            .map_err(to_py_err),
        }
    } else if recipient.algorithm().can_encrypt() {
        match version {
            EncryptionVersion::SeipdV1 => PgpPublicKeyEncryptedSessionKey::from_session_key_v3(
                rand::thread_rng(),
                &session_key,
                symmetric_algorithm,
                recipient,
            )
            .map_err(to_py_err),
            EncryptionVersion::SeipdV2 => PgpPublicKeyEncryptedSessionKey::from_session_key_v6(
                rand::thread_rng(),
                &session_key,
                recipient,
            )
            .map_err(to_py_err),
        }
    } else {
        Err(to_py_err(
            "public key does not contain an encryption-capable primary key or subkey",
        ))
    }
}

fn encrypt_session_key_with_password_inner(
    session_key: &[u8],
    password: &str,
    version: EncryptionVersion,
    symmetric_algorithm: SymmetricKeyAlgorithm,
    aead_algorithm: AeadAlgorithm,
) -> PyResult<PgpSymKeyEncryptedSessionKey> {
    let session_key = raw_session_key_from_bytes(session_key, symmetric_algorithm)?;
    let password = Password::from(password);
    match version {
        EncryptionVersion::SeipdV1 => PgpSymKeyEncryptedSessionKey::encrypt_v4(
            &password,
            &session_key,
            PgpStringToKey::new_default(rand::thread_rng()),
            symmetric_algorithm,
        )
        .map_err(to_py_err),
        EncryptionVersion::SeipdV2 => PgpSymKeyEncryptedSessionKey::encrypt_v6(
            rand::thread_rng(),
            &password,
            &session_key,
            PgpStringToKey::new_default(rand::thread_rng()),
            symmetric_algorithm,
            aead_algorithm,
        )
        .map_err(to_py_err),
    }
}

/// Encrypt a raw session key to a public-key recipient and expose the PKESK packet.
#[pyfunction]
#[pyo3(signature = (
    session_key,
    recipient,
    version="seipd-v2",
    symmetric_algorithm="aes256",
))]
fn encrypt_session_key_to_recipient(
    session_key: &[u8],
    recipient: PyRef<'_, PublicKey>,
    version: &str,
    symmetric_algorithm: &str,
) -> PyResult<PublicKeyEncryptedSessionKeyPacket> {
    let version = encryption_version_from_name(version)?;
    let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
    let inner = encrypt_session_key_to_recipient_inner(
        session_key,
        &recipient.inner,
        version,
        symmetric_algorithm,
    )?;
    Ok(PublicKeyEncryptedSessionKeyPacket { inner })
}

/// Encrypt a raw session key to a password and expose the SKESK packet.
#[pyfunction]
#[pyo3(signature = (
    session_key,
    password,
    version="seipd-v2",
    symmetric_algorithm="aes256",
    aead_algorithm="ocb",
))]
fn encrypt_session_key_with_password(
    session_key: &[u8],
    password: &str,
    version: &str,
    symmetric_algorithm: &str,
    aead_algorithm: &str,
) -> PyResult<SymKeyEncryptedSessionKeyPacket> {
    let version = encryption_version_from_name(version)?;
    let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
    let aead_algorithm = aead_algorithm_from_name(aead_algorithm)?;
    let inner = encrypt_session_key_with_password_inner(
        session_key,
        password,
        version,
        symmetric_algorithm,
        aead_algorithm,
    )?;
    Ok(SymKeyEncryptedSessionKeyPacket { inner })
}

/// Encrypt a message to a public-key recipient and return the result as binary packets.
#[pyfunction]
#[pyo3(signature = (
    data,
    recipient,
    file_name="",
    version="seipd-v2",
    symmetric_algorithm="aes256",
    aead_algorithm="ocb",
    compression=None,
    session_key=None,
))]
fn encrypt_message_to_recipient_bytes(
    data: &[u8],
    recipient: PyRef<'_, PublicKey>,
    file_name: &str,
    version: &str,
    symmetric_algorithm: &str,
    aead_algorithm: &str,
    compression: Option<&str>,
    session_key: Option<&[u8]>,
) -> PyResult<Vec<u8>> {
    let version = encryption_version_from_name(version)?;
    let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
    let aead_algorithm = aead_algorithm_from_name(aead_algorithm)?;
    let compression = compression_algorithm_from_name(compression)?;

    match version {
        EncryptionVersion::SeipdV1 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v1(rand::thread_rng(), symmetric_algorithm);
            if let Some(compression) = compression {
                builder.compression(compression);
            }
            if let Some(session_key) = session_key {
                builder
                    .set_session_key(raw_session_key_from_bytes(session_key, symmetric_algorithm)?)
                    .map_err(to_py_err)?;
            }
            encrypt_to_recipient!(builder, recipient);
            builder.to_vec(rand::thread_rng()).map_err(to_py_err)
        }
        EncryptionVersion::SeipdV2 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v2(
                        rand::thread_rng(),
                        symmetric_algorithm,
                        aead_algorithm,
                        ChunkSize::default(),
                    );
            if let Some(compression) = compression {
                builder.compression(compression);
            }
            if let Some(session_key) = session_key {
                builder
                    .set_session_key(raw_session_key_from_bytes(session_key, symmetric_algorithm)?)
                    .map_err(to_py_err)?;
            }
            encrypt_to_recipient!(builder, recipient);
            builder.to_vec(rand::thread_rng()).map_err(to_py_err)
        }
    }
}

/// Encrypt a message to a public-key recipient and return the result as ASCII armor.
#[pyfunction]
#[pyo3(signature = (
    data,
    recipient,
    file_name="",
    version="seipd-v2",
    symmetric_algorithm="aes256",
    aead_algorithm="ocb",
    compression=None,
    session_key=None,
))]
fn encrypt_message_to_recipient(
    data: &[u8],
    recipient: PyRef<'_, PublicKey>,
    file_name: &str,
    version: &str,
    symmetric_algorithm: &str,
    aead_algorithm: &str,
    compression: Option<&str>,
    session_key: Option<&[u8]>,
) -> PyResult<String> {
    let version = encryption_version_from_name(version)?;
    let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
    let aead_algorithm = aead_algorithm_from_name(aead_algorithm)?;
    let compression = compression_algorithm_from_name(compression)?;

    match version {
        EncryptionVersion::SeipdV1 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v1(rand::thread_rng(), symmetric_algorithm);
            if let Some(compression) = compression {
                builder.compression(compression);
            }
            if let Some(session_key) = session_key {
                builder
                    .set_session_key(raw_session_key_from_bytes(session_key, symmetric_algorithm)?)
                    .map_err(to_py_err)?;
            }
            encrypt_to_recipient!(builder, recipient);
            builder
                .to_armored_string(rand::thread_rng(), ArmorOptions::default())
                .map_err(to_py_err)
        }
        EncryptionVersion::SeipdV2 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v2(
                        rand::thread_rng(),
                        symmetric_algorithm,
                        aead_algorithm,
                        ChunkSize::default(),
                    );
            if let Some(compression) = compression {
                builder.compression(compression);
            }
            if let Some(session_key) = session_key {
                builder
                    .set_session_key(raw_session_key_from_bytes(session_key, symmetric_algorithm)?)
                    .map_err(to_py_err)?;
            }
            encrypt_to_recipient!(builder, recipient);
            builder
                .to_armored_string(rand::thread_rng(), ArmorOptions::default())
                .map_err(to_py_err)
        }
    }
}

/// Encrypt a message with a password and return the result as binary packets.
#[pyfunction]
#[pyo3(signature = (
    data,
    password,
    file_name="",
    version="seipd-v2",
    symmetric_algorithm="aes256",
    aead_algorithm="ocb",
    compression=None,
    session_key=None,
))]
fn encrypt_message_with_password_bytes(
    data: &[u8],
    password: &str,
    file_name: &str,
    version: &str,
    symmetric_algorithm: &str,
    aead_algorithm: &str,
    compression: Option<&str>,
    session_key: Option<&[u8]>,
) -> PyResult<Vec<u8>> {
    let version = encryption_version_from_name(version)?;
    let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
    let aead_algorithm = aead_algorithm_from_name(aead_algorithm)?;
    let compression = compression_algorithm_from_name(compression)?;
    let password = Password::from(password);

    match version {
        EncryptionVersion::SeipdV1 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v1(rand::thread_rng(), symmetric_algorithm);
            if let Some(compression) = compression {
                builder.compression(compression);
            }
            if let Some(session_key) = session_key {
                builder
                    .set_session_key(raw_session_key_from_bytes(session_key, symmetric_algorithm)?)
                    .map_err(to_py_err)?;
            }
            builder
                .encrypt_with_password(PgpStringToKey::new_default(rand::thread_rng()), &password)
                .map_err(to_py_err)?;
            builder.to_vec(rand::thread_rng()).map_err(to_py_err)
        }
        EncryptionVersion::SeipdV2 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v2(
                        rand::thread_rng(),
                        symmetric_algorithm,
                        aead_algorithm,
                        ChunkSize::default(),
                    );
            if let Some(compression) = compression {
                builder.compression(compression);
            }
            if let Some(session_key) = session_key {
                builder
                    .set_session_key(raw_session_key_from_bytes(session_key, symmetric_algorithm)?)
                    .map_err(to_py_err)?;
            }
            builder
                .encrypt_with_password(
                    rand::thread_rng(),
                    PgpStringToKey::new_default(rand::thread_rng()),
                    &password,
                )
                .map_err(to_py_err)?;
            builder.to_vec(rand::thread_rng()).map_err(to_py_err)
        }
    }
}

/// Encrypt a message with a password and return the result as ASCII armor.
#[pyfunction]
#[pyo3(signature = (
    data,
    password,
    file_name="",
    version="seipd-v2",
    symmetric_algorithm="aes256",
    aead_algorithm="ocb",
    compression=None,
    session_key=None,
))]
fn encrypt_message_with_password(
    data: &[u8],
    password: &str,
    file_name: &str,
    version: &str,
    symmetric_algorithm: &str,
    aead_algorithm: &str,
    compression: Option<&str>,
    session_key: Option<&[u8]>,
) -> PyResult<String> {
    let version = encryption_version_from_name(version)?;
    let symmetric_algorithm = symmetric_algorithm_from_name(symmetric_algorithm)?;
    let aead_algorithm = aead_algorithm_from_name(aead_algorithm)?;
    let compression = compression_algorithm_from_name(compression)?;
    let password = Password::from(password);

    match version {
        EncryptionVersion::SeipdV1 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v1(rand::thread_rng(), symmetric_algorithm);
            if let Some(compression) = compression {
                builder.compression(compression);
            }
            if let Some(session_key) = session_key {
                builder
                    .set_session_key(raw_session_key_from_bytes(session_key, symmetric_algorithm)?)
                    .map_err(to_py_err)?;
            }
            builder
                .encrypt_with_password(PgpStringToKey::new_default(rand::thread_rng()), &password)
                .map_err(to_py_err)?;
            builder
                .to_armored_string(rand::thread_rng(), ArmorOptions::default())
                .map_err(to_py_err)
        }
        EncryptionVersion::SeipdV2 => {
            let mut builder =
                MessageBuilder::from_reader(file_name.to_string(), Cursor::new(data.to_vec()))
                    .seipd_v2(
                        rand::thread_rng(),
                        symmetric_algorithm,
                        aead_algorithm,
                        ChunkSize::default(),
                    );
            if let Some(compression) = compression {
                builder.compression(compression);
            }
            if let Some(session_key) = session_key {
                builder
                    .set_session_key(raw_session_key_from_bytes(session_key, symmetric_algorithm)?)
                    .map_err(to_py_err)?;
            }
            builder
                .encrypt_with_password(
                    rand::thread_rng(),
                    PgpStringToKey::new_default(rand::thread_rng()),
                    &password,
                )
                .map_err(to_py_err)?;
            builder
                .to_armored_string(rand::thread_rng(), ArmorOptions::default())
                .map_err(to_py_err)
        }
    }
}

#[pymodule]
fn _openpgp(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<EncryptionCaps>()?;
    module.add_class::<PyPacketHeaderVersion>()?;
    module.add_class::<KeyType>()?;
    module.add_class::<PyStringToKey>()?;
    module.add_class::<PyS2kParams>()?;
    module.add_class::<SubkeyParams>()?;
    module.add_class::<SubkeyParamsBuilder>()?;
    module.add_class::<SecretKeyParams>()?;
    module.add_class::<SecretKeyParamsBuilder>()?;
    module.add_class::<PublicKey>()?;
    module.add_class::<SecretKey>()?;
    module.add_class::<PublicKeyEncryptedSessionKeyPacket>()?;
    module.add_class::<SymKeyEncryptedSessionKeyPacket>()?;
    module.add_class::<EncryptedDataPacket>()?;
    module.add_class::<Message>()?;
    module.add_class::<DecryptedMessage>()?;
    module.add_class::<KeyFlagsInfo>()?;
    module.add_class::<UserAttribute>()?;
    module.add_class::<UserAttributeBindingInfo>()?;
    module.add_class::<FeaturesInfo>()?;
    module.add_class::<PublicParamsInfo>()?;
    module.add_class::<SubkeyBindingInfo>()?;
    module.add_class::<UserBindingInfo>()?;
    module.add_class::<SignatureInfo>()?;
    module.add_class::<DetachedSignature>()?;
    module.add_class::<CleartextSignedMessage>()?;
    module.add_class::<MessageInfo>()?;
    module.add_function(wrap_pyfunction!(inspect_message, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_message_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(sign_message, module)?)?;
    module.add_function(wrap_pyfunction!(sign_cleartext_message, module)?)?;
    module.add_function(wrap_pyfunction!(encrypt_session_key_to_recipient, module)?)?;
    module.add_function(wrap_pyfunction!(encrypt_session_key_with_password, module)?)?;
    module.add_function(wrap_pyfunction!(encrypt_message_to_recipient_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(encrypt_message_to_recipient, module)?)?;
    module.add_function(wrap_pyfunction!(encrypt_message_with_password_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(encrypt_message_with_password, module)?)?;
    Ok(())
}
