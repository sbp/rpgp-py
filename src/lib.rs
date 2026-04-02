use std::{collections::BTreeMap, io::Cursor};

use pgp::{
    composed::{
        ArmorOptions, CleartextSignedMessage as PgpCleartextSignedMessage, Deserializable,
        DetachedSignature as PgpDetachedSignature, Message as PgpMessage, MessageBuilder,
        SignedPublicKey, SignedSecretKey,
    },
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        hash::HashAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::DataMode,
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

    /// Verify a signed message against a public key.
    fn verify(&self, key: PyRef<'_, PublicKey>) -> PyResult<()> {
        let mut message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        message.verify_read(&key.inner).map_err(to_py_err)?;
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

    /// Verify a detached signature against a public key and payload.
    fn verify(&self, key: PyRef<'_, PublicKey>, data: &[u8]) -> PyResult<()> {
        self.inner.verify(&key.inner, data).map_err(to_py_err)
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

    /// Verify at least one cleartext signature against the given public key.
    fn verify(&self, key: PyRef<'_, PublicKey>) -> PyResult<()> {
        self.inner
            .verify(&key.inner.primary_key)
            .map(|_| ())
            .map_err(to_py_err)
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
