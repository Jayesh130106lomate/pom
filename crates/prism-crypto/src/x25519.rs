use x25519_dalek::{StaticSecret, PublicKey, SharedSecret};
use rand::rngs::OsRng;
use zeroize::Zeroize;

pub struct X25519Secret(pub StaticSecret);

impl Zeroize for X25519Secret {
    fn zeroize(&mut self) {
        self.0 = StaticSecret::from([0u8; 32]);
    }
}

impl Drop for X25519Secret {
    fn drop(&mut self) {
        // Zeroized automatically
    }
}

#[derive(Clone, Copy, Debug)]
pub struct X25519Public(pub PublicKey);

pub fn generate_keypair() -> (X25519Secret, X25519Public) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (X25519Secret(secret), X25519Public(public))
}

pub fn diffie_hellman(secret: &X25519Secret, their_public: &X25519Public) -> SharedSecret {
    secret.0.diffie_hellman(&their_public.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_dh() {
        let (alice_sec, alice_pub) = generate_keypair();
        let (bob_sec, bob_pub) = generate_keypair();
        
        let alice_shared = diffie_hellman(&alice_sec, &bob_pub);
        let bob_shared = diffie_hellman(&bob_sec, &alice_pub);
        
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }
}
