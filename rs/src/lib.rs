use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Signature, Verifier};
use rand::rngs::OsRng;

// generate signing key ([u8; 32])
pub fn sk() -> [u8; 32] {
    let mut rng: OsRng = OsRng;
    let sk: SigningKey = SigningKey::generate(&mut rng);
    sk.to_bytes()
}

// generate verifying key ([u8; 32]) from signing key ([u8; 32])
pub fn vk(sk_bytes: [u8; 32]) -> [u8; 32]{
    let sk: SigningKey = SigningKey::from(sk_bytes);
    let vk: VerifyingKey = sk.verifying_key();
    vk.to_bytes()
}

pub fn sign(sk_bytes: [u8; 32], data: &[u8]) -> [u8; 64] {
    let sk: SigningKey = SigningKey::from(sk_bytes);
    let s: Signature =  sk.sign(data);
    s.to_bytes()
}

pub fn verify(vk_bytes: &[u8; 32], data: &[u8], s_bytes: &[u8; 64]) -> bool {
    let vk: VerifyingKey = VerifyingKey::from_bytes(vk_bytes).unwrap();
    let s: Signature = Signature::from_bytes(s_bytes);
    match vk.verify(data, &s) {
        Ok(_) => true,
        Err(_) => false,
    }
} 