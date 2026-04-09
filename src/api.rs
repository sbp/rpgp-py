use crate::*;
use crate::conversions::*;
use crate::info::*;
use crate::keys::*;
use crate::packets::*;
use crate::serialization::*;

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

/// Inspect an ASCII-armored or binary OpenPGP message without exposing its payload.
#[pyfunction]
pub(crate) fn inspect_message(data: &str) -> PyResult<MessageInfo> {
    parse_message_info_from_reader(Cursor::new(data.as_bytes())).map_err(to_py_err)
}

/// Inspect a binary OpenPGP message without exposing its payload.
#[pyfunction]
pub(crate) fn inspect_message_bytes(data: &[u8]) -> PyResult<MessageInfo> {
    parse_message_info_from_reader(Cursor::new(data)).map_err(to_py_err)
}

/// Create a simple binary signed message and return it as ASCII armor.
#[pyfunction]
#[pyo3(signature = (data, signer, password=None, file_name=""))]
pub(crate) fn sign_message(
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
pub(crate) fn sign_cleartext_message(
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

pub(crate) fn encrypt_session_key_to_recipient_inner(
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

pub(crate) fn encrypt_session_key_with_password_inner(
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
pub(crate) fn encrypt_session_key_to_recipient(
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
pub(crate) fn encrypt_session_key_with_password(
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
pub(crate) fn encrypt_message_to_recipient_bytes(
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
pub(crate) fn encrypt_message_to_recipient(
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
pub(crate) fn encrypt_message_with_password_bytes(
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
pub(crate) fn encrypt_message_with_password(
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
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(pyo3::wrap_pyfunction!(inspect_message, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(inspect_message_bytes, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(sign_message, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(sign_cleartext_message, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(encrypt_session_key_to_recipient, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(encrypt_session_key_with_password, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(encrypt_message_to_recipient_bytes, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(encrypt_message_to_recipient, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(encrypt_message_with_password_bytes, module)?)?;
    module.add_function(pyo3::wrap_pyfunction!(encrypt_message_with_password, module)?)?;
    Ok(())
}
