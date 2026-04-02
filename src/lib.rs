use std::{collections::BTreeMap, io::Cursor};

use pgp::{
    composed::{
        ArmorOptions, CleartextSignedMessage as PgpCleartextSignedMessage, Deserializable,
        DetachedSignature as PgpDetachedSignature, FullSignaturePacket, Message as PgpMessage,
        MessageBuilder, SignedPublicKey, SignedSecretKey,
    },
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        hash::HashAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::{DataMode, Signature, SignatureType, SignatureVersion, SignatureVersionSpecific},
    ser::Serialize,
    types::{CompressionAlgorithm, KeyDetails, Password, StringToKey},
};
use pyo3::{
    exceptions::PyValueError,
    prelude::*,
    types::{PyModule, PyModuleMethods},
};

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

fn message_info_from_parts(message: PgpMessage<'_>, headers: Option<Headers>) -> MessageInfo {
    let (kind, is_nested) = match message {
        PgpMessage::Literal { is_nested, .. } => ("literal", is_nested),
        PgpMessage::Compressed { is_nested, .. } => ("compressed", is_nested),
        PgpMessage::Signed { is_nested, .. } => ("signed", is_nested),
        PgpMessage::Encrypted { is_nested, .. } => ("encrypted", is_nested),
    };

    MessageInfo {
        kind: kind.to_string(),
        is_nested,
        headers,
    }
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

fn password_from_option(password: Option<&str>) -> Password {
    match password {
        Some(password) if !password.is_empty() => password.into(),
        _ => Password::empty(),
    }
}

fn lossy_user_ids(details: &pgp::composed::SignedKeyDetails) -> Vec<String> {
    details
        .users
        .iter()
        .map(|user| String::from_utf8_lossy(user.id.id()).into_owned())
        .collect()
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

fn signature_info_from_signature(signature: &Signature, is_one_pass: bool) -> SignatureInfo {
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
        is_one_pass,
    }
}

fn signature_info_from_full_signature(signature: &FullSignaturePacket) -> SignatureInfo {
    let is_one_pass = matches!(signature, FullSignaturePacket::Ops { .. });
    signature_info_from_signature(signature.signature(), is_one_pass)
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

    Ok(DecryptedMessage {
        kind: kind.to_string(),
        is_nested,
        is_signed,
        is_compressed,
        is_literal,
        payload,
        literal_mode,
        literal_filename,
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
        let mut message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        if matches!(message, PgpMessage::Encrypted { .. }) {
            return Err(to_py_err(
                "message must be decrypted before reading payload",
            ));
        }
        message.as_data_vec().map_err(to_py_err)
    }

    /// Read the inner payload as UTF-8 text, automatically decompressing nested compressed layers.
    fn payload_text(&self) -> PyResult<String> {
        let mut message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        if matches!(message, PgpMessage::Encrypted { .. }) {
            return Err(to_py_err(
                "message must be decrypted before reading payload",
            ));
        }
        message.as_data_string().map_err(to_py_err)
    }

    /// Return the literal data mode after automatic decompression, if a literal layer exists.
    fn literal_mode(&self) -> PyResult<Option<String>> {
        let message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        Ok(message
            .literal_data_header()
            .map(|header| data_mode_name(header.mode())))
    }

    /// Return the literal file name octets after automatic decompression, if available.
    fn literal_filename(&self) -> PyResult<Option<Vec<u8>>> {
        let message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        Ok(message
            .literal_data_header()
            .map(|header| header.file_name().to_vec()))
    }

    /// Return the number of signatures after automatic decompression.
    ///
    /// For signed messages this includes both one-pass and prefixed signatures.
    fn signature_count(&self) -> PyResult<usize> {
        let message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        match message {
            PgpMessage::Signed { reader, .. } => Ok(reader.num_signatures()),
            PgpMessage::Encrypted { .. } => Err(to_py_err(
                "message must be decrypted before inspecting signatures",
            )),
            _ => Ok(0),
        }
    }

    /// Return the number of one-pass signatures after automatic decompression.
    fn one_pass_signature_count(&self) -> PyResult<usize> {
        let message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        match message {
            PgpMessage::Signed { reader, .. } => Ok(reader.num_one_pass_signatures()),
            PgpMessage::Encrypted { .. } => Err(to_py_err(
                "message must be decrypted before inspecting signatures",
            )),
            _ => Ok(0),
        }
    }

    /// Return the number of prefixed (non-one-pass) signatures after automatic decompression.
    fn regular_signature_count(&self) -> PyResult<usize> {
        let message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        match message {
            PgpMessage::Signed { reader, .. } => Ok(reader.num_regular_signatures()),
            PgpMessage::Encrypted { .. } => Err(to_py_err(
                "message must be decrypted before inspecting signatures",
            )),
            _ => Ok(0),
        }
    }

    /// Return metadata for each signature packet on a signed message.
    ///
    /// This reads the message to the end to finalize one-pass signature verification state,
    /// mirroring the requirements of RFC 9580 one-pass signatures.
    fn signature_infos(&self) -> PyResult<Vec<SignatureInfo>> {
        let message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        signature_infos_from_signed_message(message)
    }

    /// Verify a specific signature on the message and return its metadata.
    ///
    /// The default index of ``0`` corresponds to the first signature reported by
    /// :meth:`signature_infos`.
    #[pyo3(signature = (key, index=0))]
    fn verify_signature(&self, key: PyRef<'_, PublicKey>, index: usize) -> PyResult<SignatureInfo> {
        let message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        verify_message_signature_info(message, &key.inner, index)
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
    fn decrypt_with_password(&self, password: &str) -> PyResult<DecryptedMessage> {
        let message_password = Password::from(password);
        let (message, _) = parse_message(&self.source).map_err(to_py_err)?;
        let decrypted = message
            .decrypt_with_password(&message_password)
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

/// A decrypted OpenPGP message with eagerly extracted payload and metadata.
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

    fn __repr__(&self) -> String {
        format!(
            "DecryptedMessage(kind='{}', is_nested={})",
            self.kind, self.is_nested
        )
    }
}

/// Metadata extracted from an OpenPGP data signature packet.
///
/// The fields mirror the RFC 9580 signature packet configuration, including issuer subpackets,
/// the 16-bit signed hash prefix, and the version-6 salt when present.
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
))]
fn encrypt_message_to_recipient(
    data: &[u8],
    recipient: PyRef<'_, PublicKey>,
    file_name: &str,
    version: &str,
    symmetric_algorithm: &str,
    aead_algorithm: &str,
    compression: Option<&str>,
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
            encrypt_to_recipient!(builder, recipient);
            builder
                .to_armored_string(rand::thread_rng(), ArmorOptions::default())
                .map_err(to_py_err)
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
))]
fn encrypt_message_with_password(
    data: &[u8],
    password: &str,
    file_name: &str,
    version: &str,
    symmetric_algorithm: &str,
    aead_algorithm: &str,
    compression: Option<&str>,
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
            builder
                .encrypt_with_password(StringToKey::new_default(rand::thread_rng()), &password)
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
            builder
                .encrypt_with_password(
                    rand::thread_rng(),
                    StringToKey::new_default(rand::thread_rng()),
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
    module.add_class::<PublicKey>()?;
    module.add_class::<SecretKey>()?;
    module.add_class::<Message>()?;
    module.add_class::<DecryptedMessage>()?;
    module.add_class::<SignatureInfo>()?;
    module.add_class::<DetachedSignature>()?;
    module.add_class::<CleartextSignedMessage>()?;
    module.add_class::<MessageInfo>()?;
    module.add_function(wrap_pyfunction!(inspect_message, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_message_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(sign_message, module)?)?;
    module.add_function(wrap_pyfunction!(sign_cleartext_message, module)?)?;
    module.add_function(wrap_pyfunction!(encrypt_message_to_recipient, module)?)?;
    module.add_function(wrap_pyfunction!(encrypt_message_with_password, module)?)?;
    Ok(())
}
