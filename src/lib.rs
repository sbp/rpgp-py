use std::{collections::BTreeMap, io::Cursor};

use pgp::{
    composed::{
        ArmorOptions, Deserializable, DetachedSignature as PgpDetachedSignature,
        Message as PgpMessage, MessageBuilder, SignedPublicKey, SignedSecretKey,
    },
    crypto::hash::HashAlgorithm,
    packet::DataMode,
    ser::Serialize,
    types::Password,
    types::KeyDetails,
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

#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct PublicKey {
    inner: SignedPublicKey,
}

#[pymethods]
impl PublicKey {
    #[staticmethod]
    fn from_armor(data: &str) -> PyResult<(Self, Headers)> {
        let (inner, headers) = SignedPublicKey::from_string(data).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = SignedPublicKey::from_bytes(Cursor::new(data)).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    #[getter]
    fn fingerprint(&self) -> String {
        self.inner.fingerprint().to_string()
    }

    #[getter]
    fn key_id(&self) -> String {
        self.inner.legacy_key_id().to_string()
    }

    #[getter]
    fn public_subkey_count(&self) -> usize {
        self.inner.public_subkeys.len()
    }

    #[getter]
    fn user_ids(&self) -> Vec<String> {
        lossy_user_ids(&self.inner.details)
    }

    fn verify_bindings(&self) -> PyResult<()> {
        self.inner.verify_bindings().map_err(to_py_err)
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

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

#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct SecretKey {
    inner: SignedSecretKey,
}

#[pymethods]
impl SecretKey {
    #[staticmethod]
    fn from_armor(data: &str) -> PyResult<(Self, Headers)> {
        let (inner, headers) = SignedSecretKey::from_string(data).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = SignedSecretKey::from_bytes(Cursor::new(data)).map_err(to_py_err)?;
        Ok(Self { inner })
    }

    #[getter]
    fn fingerprint(&self) -> String {
        self.inner.primary_key.public_key().fingerprint().to_string()
    }

    #[getter]
    fn key_id(&self) -> String {
        self.inner.primary_key.public_key().legacy_key_id().to_string()
    }

    #[getter]
    fn public_subkey_count(&self) -> usize {
        self.inner.public_subkeys.len()
    }

    #[getter]
    fn secret_subkey_count(&self) -> usize {
        self.inner.secret_subkeys.len()
    }

    #[getter]
    fn user_ids(&self) -> Vec<String> {
        lossy_user_ids(&self.inner.details)
    }

    fn verify_bindings(&self) -> PyResult<()> {
        self.inner.verify_bindings().map_err(to_py_err)
    }

    fn to_public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.to_public_key(),
        }
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

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

#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct Message {
    source: Vec<u8>,
    info: MessageInfo,
}

#[pymethods]
impl Message {
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

    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let info = inspect_message_from_source(data).map_err(to_py_err)?;
        Ok(Self {
            source: data.to_vec(),
            info,
        })
    }

    #[getter]
    fn kind(&self) -> String {
        self.info.kind.clone()
    }

    #[getter]
    fn is_nested(&self) -> bool {
        self.info.is_nested
    }

    #[getter]
    fn headers(&self) -> Option<Headers> {
        self.info.headers.clone()
    }

    #[getter]
    fn is_signed(&self) -> bool {
        self.kind() == "signed"
    }

    #[getter]
    fn is_compressed(&self) -> bool {
        self.kind() == "compressed"
    }

    #[getter]
    fn is_literal(&self) -> bool {
        self.kind() == "literal"
    }

    fn payload_bytes(&self) -> PyResult<Vec<u8>> {
        let mut message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        if matches!(message, PgpMessage::Encrypted { .. }) {
            return Err(to_py_err("message must be decrypted before reading payload"));
        }
        message.as_data_vec().map_err(to_py_err)
    }

    fn payload_text(&self) -> PyResult<String> {
        let mut message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        if matches!(message, PgpMessage::Encrypted { .. }) {
            return Err(to_py_err("message must be decrypted before reading payload"));
        }
        message.as_data_string().map_err(to_py_err)
    }

    fn literal_mode(&self) -> PyResult<Option<String>> {
        let message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        Ok(message.literal_data_header().map(|header| data_mode_name(header.mode())))
    }

    fn literal_filename(&self) -> PyResult<Option<Vec<u8>>> {
        let message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        Ok(message
            .literal_data_header()
            .map(|header| header.file_name().to_vec()))
    }

    fn verify(&self, key: PyRef<'_, PublicKey>) -> PyResult<()> {
        let mut message = prepare_message_for_content(&self.source).map_err(to_py_err)?;
        message.verify_read(&key.inner).map_err(to_py_err)?;
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!(
            "Message(kind='{}', is_nested={})",
            self.info.kind, self.info.is_nested
        )
    }
}

#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct DetachedSignature {
    inner: PgpDetachedSignature,
}

#[pymethods]
impl DetachedSignature {
    #[staticmethod]
    fn from_armor(data: &str) -> PyResult<(Self, Headers)> {
        let (inner, headers) = PgpDetachedSignature::from_string(data).map_err(to_py_err)?;
        Ok((Self { inner }, headers))
    }

    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let inner = PgpDetachedSignature::from_bytes(Cursor::new(data)).map_err(to_py_err)?;
        Ok(Self { inner })
    }

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

    fn verify(&self, key: PyRef<'_, PublicKey>, data: &[u8]) -> PyResult<()> {
        self.inner.verify(&key.inner, data).map_err(to_py_err)
    }

    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        self.inner.to_bytes().map_err(to_py_err)
    }

    fn to_armored(&self) -> PyResult<String> {
        self.inner
            .to_armored_string(ArmorOptions::default())
            .map_err(to_py_err)
    }

    fn __repr__(&self) -> String {
        "DetachedSignature()".to_string()
    }
}

#[pyclass(module = "openpgp")]
#[derive(Clone)]
struct MessageInfo {
    kind: String,
    is_nested: bool,
    headers: Option<Headers>,
}

#[pymethods]
impl MessageInfo {
    #[getter]
    fn kind(&self) -> String {
        self.kind.clone()
    }

    #[getter]
    fn is_nested(&self) -> bool {
        self.is_nested
    }

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

#[pyfunction]
fn inspect_message(data: &str) -> PyResult<MessageInfo> {
    parse_message_info_from_reader(Cursor::new(data.as_bytes())).map_err(to_py_err)
}

#[pyfunction]
fn inspect_message_bytes(data: &[u8]) -> PyResult<MessageInfo> {
    parse_message_info_from_reader(Cursor::new(data)).map_err(to_py_err)
}

#[pyfunction]
#[pyo3(signature = (data, signer, password=None, file_name=""))]
fn sign_message(
    data: &[u8],
    signer: PyRef<'_, SecretKey>,
    password: Option<&str>,
    file_name: &str,
) -> PyResult<String> {
    let password = password_from_option(password);
    let mut builder = MessageBuilder::from_bytes(file_name.to_string(), data.to_vec());
    builder.sign(&signer.inner.primary_key, password, HashAlgorithm::Sha256);
    builder
        .to_armored_string(&mut rand::thread_rng(), ArmorOptions::default())
        .map_err(to_py_err)
}

#[pymodule]
fn _openpgp(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PublicKey>()?;
    module.add_class::<SecretKey>()?;
    module.add_class::<Message>()?;
    module.add_class::<DetachedSignature>()?;
    module.add_class::<MessageInfo>()?;
    module.add_function(wrap_pyfunction!(inspect_message, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_message_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(sign_message, module)?)?;
    Ok(())
}
