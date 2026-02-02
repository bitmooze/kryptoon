// IMPORT
use chacha20poly1305::{aead::{Aead, Payload, KeyInit}, ChaCha20Poly1305, XChaCha20Poly1305, Key, Nonce, XNonce};
use pyo3::exceptions::*;
use pyo3::prelude::*;

// MAIN
#[pyfunction]
pub fn chencrypt(secretkey: &[u8], nonce: &[u8], buffer: &[u8], aad: Option<&[u8]>) -> PyResult<Vec<u8>> {
    if secretkey.len() != 32 {
        return Err(PyRuntimeError::new_err("Key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(PyRuntimeError::new_err("Nonce must be 12 bytes"));
    }
    //
    let internalkey = Key::from_slice(secretkey);
    let internalcipher = ChaCha20Poly1305::new(internalkey);
    let internalnonce = Nonce::from_slice(nonce);
    //
    let ciphertext = match aad {
        Some(internalaad) => internalcipher.encrypt(internalnonce, Payload { msg: buffer, aad: internalaad }),
        None => internalcipher.encrypt(internalnonce, buffer),
    }.map_err(|_| PyRuntimeError::new_err("Encryption failed"))?;
    //
    Ok(ciphertext)
}

#[pyfunction]
pub fn chdecrypt(secretkey: &[u8], nonce: &[u8], buffer: &[u8], aad: Option<&[u8]>) -> PyResult<Vec<u8>> {
    if secretkey.len() != 32 {
        return Err(PyRuntimeError::new_err("Key must be 32 bytes"));
    }
    if nonce.len() != 12 {
        return Err(PyRuntimeError::new_err("Nonce must be 12 bytes"));
    }
    //
    let internalkey = Key::from_slice(secretkey);
    let internalcipher = ChaCha20Poly1305::new(internalkey);
    let internalnonce = Nonce::from_slice(nonce);
    //
    let ciphertext = match aad {
        Some(internalaad) => internalcipher.decrypt(internalnonce, Payload { msg: buffer, aad: internalaad }),
        None => internalcipher.decrypt(internalnonce, buffer),
    }.map_err(|_| PyRuntimeError::new_err("Decryption failed"))?;
    //
    Ok(ciphertext)
}

#[pyfunction]
pub fn xchencrypt(secretkey: &[u8], nonce: &[u8], buffer: &[u8], aad: Option<&[u8]>) -> PyResult<Vec<u8>> {
    if secretkey.len() != 32 {
        return Err(PyRuntimeError::new_err("Key must be 32 bytes"));
    }
    if nonce.len() != 24 {
        return Err(PyRuntimeError::new_err("Nonce must be 24 bytes"));
    }
    //
    let internalkey = Key::from_slice(secretkey);
    let internalcipher = XChaCha20Poly1305::new(internalkey);
    let internalnonce = XNonce::from_slice(nonce);
    //
    let ciphertext = match aad {
        Some(internalaad) => internalcipher.encrypt(internalnonce, Payload { msg: buffer, aad: internalaad }),
        None => internalcipher.encrypt(internalnonce, buffer),
    }.map_err(|_| PyRuntimeError::new_err("Encryption failed"))?;
    //
    Ok(ciphertext)
}

#[pyfunction]
pub fn xchdecrypt(secretkey: &[u8], nonce: &[u8], buffer: &[u8], aad: Option<&[u8]>) -> PyResult<Vec<u8>> {
    if secretkey.len() != 32 {
        return Err(PyRuntimeError::new_err("Key must be 32 bytes"));
    }
    if nonce.len() != 24 {
        return Err(PyRuntimeError::new_err("Nonce must be 24 bytes"));
    }
    //
    let internalkey = Key::from_slice(secretkey);
    let internalcipher = XChaCha20Poly1305::new(internalkey);
    let internalnonce = XNonce::from_slice(nonce);
    //
    let ciphertext = match aad {
        Some(internalaad) => internalcipher.decrypt(internalnonce, Payload { msg: buffer, aad: internalaad }),
        None => internalcipher.decrypt(internalnonce, buffer),
    }.map_err(|_| PyRuntimeError::new_err("Decryption failed"))?;
    //
    Ok(ciphertext)
}
