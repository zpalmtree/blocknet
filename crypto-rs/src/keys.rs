use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use ed25519_dalek::Signer;
use std::slice;

/// Generate a new ed25519 keypair
/// Returns: 32-byte private key || 32-byte public key (64 bytes total)
#[no_mangle]
pub extern "C" fn blocknet_generate_keypair(output: *mut u8) -> i32 {
    if output.is_null() {
        return -1;
    }

    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let verifying_key = signing_key.verifying_key();

    unsafe {
        let output_slice = slice::from_raw_parts_mut(output, 64);
        output_slice[..32].copy_from_slice(&signing_key.to_bytes());
        output_slice[32..].copy_from_slice(&verifying_key.to_bytes());
    }

    0
}

/// Sign a message with ed25519
#[no_mangle]
pub extern "C" fn blocknet_sign(
    private_key: *const u8,
    message: *const u8,
    message_len: usize,
    signature_out: *mut u8,
) -> i32 {
    if private_key.is_null() || message.is_null() || signature_out.is_null() {
        return -1;
    }

    unsafe {
        let key_bytes = slice::from_raw_parts(private_key, 32);
        let msg_bytes = slice::from_raw_parts(message, message_len);

        let signing_key = SigningKey::from_bytes(
            key_bytes.try_into().expect("slice with incorrect length")
        );

        let signature = signing_key.sign(msg_bytes);

        let sig_out = slice::from_raw_parts_mut(signature_out, 64);
        sig_out.copy_from_slice(&signature.to_bytes());
    }

    0
}

/// Verify an ed25519 signature
#[no_mangle]
pub extern "C" fn blocknet_verify(
    public_key: *const u8,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
) -> i32 {
    if public_key.is_null() || message.is_null() || signature.is_null() {
        return -1;
    }

    unsafe {
        let pub_bytes = slice::from_raw_parts(public_key, 32);
        let msg_bytes = slice::from_raw_parts(message, message_len);
        let sig_bytes = slice::from_raw_parts(signature, 64);

        let verifying_key = match VerifyingKey::from_bytes(
            pub_bytes.try_into().expect("slice with incorrect length")
        ) {
            Ok(key) => key,
            Err(_) => return -1,
        };

        let sig = Signature::from_bytes(
            sig_bytes.try_into().expect("slice with incorrect length")
        );

        match verifying_key.verify(msg_bytes, &sig) {
            Ok(_) => 0,
            Err(_) => -1,
        }
    }
}

/// Schnorr sign over Ristretto255.
/// private_key: 32-byte Ristretto scalar (the wallet spend private key)
/// signature_out: 64 bytes (32-byte compressed R || 32-byte scalar s)
#[no_mangle]
pub extern "C" fn blocknet_schnorr_sign(
    private_key: *const u8,
    message: *const u8,
    message_len: usize,
    signature_out: *mut u8,
) -> i32 {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    if private_key.is_null() || message.is_null() || signature_out.is_null() {
        return -1;
    }

    unsafe {
        let priv_bytes = slice::from_raw_parts(private_key, 32);
        let msg_bytes = slice::from_raw_parts(message, message_len);

        let x = match Scalar::from_canonical_bytes(
            priv_bytes.try_into().expect("slice length"),
        )
        .into_option()
        {
            Some(s) => s,
            None => return -1,
        };

        let pubkey = (&x * RISTRETTO_BASEPOINT_TABLE).compress();

        // Deterministic nonce: k = H("blocknet_schnorr_nonce" || privkey || message) mod l
        let k = {
            let mut h = Sha512::new();
            h.update(b"blocknet_schnorr_nonce");
            h.update(priv_bytes);
            h.update(msg_bytes);
            Scalar::from_hash(h)
        };

        let r_point = (&k * RISTRETTO_BASEPOINT_TABLE).compress();

        // Challenge: e = H("blocknet_schnorr_challenge" || R || pubkey || message) mod l
        let e = {
            let mut h = Sha512::new();
            h.update(b"blocknet_schnorr_challenge");
            h.update(r_point.as_bytes());
            h.update(pubkey.as_bytes());
            h.update(msg_bytes);
            Scalar::from_hash(h)
        };

        let s = k + e * x;

        let sig_out = slice::from_raw_parts_mut(signature_out, 64);
        sig_out[..32].copy_from_slice(r_point.as_bytes());
        sig_out[32..].copy_from_slice(s.as_bytes());
    }

    0
}

/// Schnorr verify over Ristretto255.
/// public_key: 32-byte compressed RistrettoPoint (the spend_pub from the address)
/// signature: 64 bytes (32-byte compressed R || 32-byte scalar s)
#[no_mangle]
pub extern "C" fn blocknet_schnorr_verify(
    public_key: *const u8,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
) -> i32 {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    if public_key.is_null() || message.is_null() || signature.is_null() {
        return -1;
    }

    unsafe {
        let pub_bytes = slice::from_raw_parts(public_key, 32);
        let msg_bytes = slice::from_raw_parts(message, message_len);
        let sig_bytes = slice::from_raw_parts(signature, 64);

        let pubkey_compressed = CompressedRistretto::from_slice(&pub_bytes[..32])
            .expect("slice length");
        let pubkey = match pubkey_compressed.decompress() {
            Some(p) => p,
            None => return -1,
        };

        let r_compressed = CompressedRistretto::from_slice(&sig_bytes[..32])
            .expect("slice length");
        let r_point = match r_compressed.decompress() {
            Some(p) => p,
            None => return -1,
        };

        let s = match Scalar::from_canonical_bytes(
            sig_bytes[32..64].try_into().expect("slice length"),
        )
        .into_option()
        {
            Some(s) => s,
            None => return -1,
        };

        // Recompute challenge
        let e = {
            let mut h = Sha512::new();
            h.update(b"blocknet_schnorr_challenge");
            h.update(r_compressed.as_bytes());
            h.update(pubkey_compressed.as_bytes());
            h.update(msg_bytes);
            Scalar::from_hash(h)
        };

        // Verify: s*G == R + e*P
        let lhs = &s * RISTRETTO_BASEPOINT_TABLE;
        let rhs = r_point + e * pubkey;

        if lhs == rhs { 0 } else { -1 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let mut output = [0u8; 64];
        let result = blocknet_generate_keypair(output.as_mut_ptr());
        assert_eq!(result, 0);
        assert_ne!(&output[..32], &[0u8; 32]);
    }

    #[test]
    fn test_sign_verify() {
        let mut keypair = [0u8; 64];
        blocknet_generate_keypair(keypair.as_mut_ptr());

        let message = b"Hello, blocknet!";
        let mut signature = [0u8; 64];

        let sign_result = blocknet_sign(
            keypair.as_ptr(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
        );
        assert_eq!(sign_result, 0);

        let verify_result = blocknet_verify(
            keypair[32..].as_ptr(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
        );
        assert_eq!(verify_result, 0);
    }

    #[test]
    fn test_schnorr_sign_verify_ristretto() {
        use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
        use curve25519_dalek::scalar::Scalar;

        let privkey = Scalar::random(&mut rand::thread_rng());
        let pubkey = (&privkey * RISTRETTO_BASEPOINT_TABLE).compress();

        let message = b"blocknet-auth:1:test:abc123:1708531200";
        let mut signature = [0u8; 64];

        let sign_result = blocknet_schnorr_sign(
            privkey.as_bytes().as_ptr(),
            message.as_ptr(),
            message.len(),
            signature.as_mut_ptr(),
        );
        assert_eq!(sign_result, 0);

        let verify_result = blocknet_schnorr_verify(
            pubkey.as_bytes().as_ptr(),
            message.as_ptr(),
            message.len(),
            signature.as_ptr(),
        );
        assert_eq!(verify_result, 0, "valid signature must verify");

        // Tampered message must fail
        let bad_message = b"tampered message";
        let verify_bad = blocknet_schnorr_verify(
            pubkey.as_bytes().as_ptr(),
            bad_message.as_ptr(),
            bad_message.len(),
            signature.as_ptr(),
        );
        assert_ne!(verify_bad, 0, "tampered message must not verify");
    }
}

