use anyhow::Result;
use ark_ec::{CurveGroup, Group};
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::Rng, UniformRand};
use hex::encode;
use num_bigint::{BigUint, ParseBigIntError};
use num_traits::Num;
use sha2::{Digest, Sha256};

const SALT_SIZE: usize = 16;

#[derive(Default, Debug)]
pub struct Proof<C: Group> {
    pub g: C, // maybe it's extra field. I think we can use enum and construct it on the fly.
    pub drand: String,
    pub commit: C,
    pub z: C::ScalarField,
}

#[derive(Debug, Default, Clone)]
pub struct GroupDescription<C: CurveGroup> {
    generator: C,
}

impl<C: CurveGroup> GroupDescription<C> {
    pub fn new() -> GroupDescription<C> {
        GroupDescription {
            generator: C::generator(),
        }
    }

    pub fn key_setup(self, pass_word: impl AsRef<[u8]>) -> Result<(C::ScalarField, C)> {
        // Generate SALT
        let mut rng = rand::thread_rng();
        let mut salt = [0u8; SALT_SIZE];
        rng.fill(&mut salt);

        // Compute HASH
        let mut hasher = Sha256::new();
        let mut uncompressed_bytes = Vec::new();
        pass_word
            .as_ref()
            .serialize_uncompressed(&mut uncompressed_bytes)?;
        hasher.update(uncompressed_bytes);
        let mut uncompressed_bytes = Vec::new();
        salt.serialize_uncompressed(&mut uncompressed_bytes)?;
        hasher.update(uncompressed_bytes);
        let hash_result = hasher.finalize();

        // HASH TO FIELD
        let hash_str = encode(hash_result);
        let hash_int = hex_to_bignum(&hash_str)?;
        let private_key: <C as Group>::ScalarField = hash_int.into();

        // COMPUTE PUBLIC KEY
        let public_key = self.generator.mul(private_key);
        Ok((private_key, public_key))
    }

    pub fn proof(
        &self,
        publik_key: C,
        private_key: C::ScalarField,
        randomness: impl AsRef<str>,
    ) -> Result<Proof<C>> {
        let mut rng = ark_std::test_rng();

        let rand = <C as Group>::ScalarField::rand(&mut rng);
        let commit = C::generator().mul(&rand);

        let randomness = randomness.as_ref();
        let challenge = hash::<C>(&commit, &publik_key, randomness)?;
        let z = private_key * challenge + rand;

        Ok(Proof {
            g: self.generator,
            drand: randomness.to_string(),
            commit,
            z,
        })
    }

    pub fn verify_proof(proof: &Proof<C>, public_key: &C, randomness: impl AsRef<str>) -> bool {
        let challenge = hash::<C>(&proof.commit, public_key, randomness.as_ref())
            .expect("Expected correct hashing");
        let commit = proof.commit;
        let lef_hand = commit + (public_key.mul(&challenge));
        let right_hand = proof.g.mul(&proof.z);
        lef_hand == right_hand
    }
}

pub fn hash<C: CurveGroup>(x: &C, y: &C, r: &str) -> Result<<C as Group>::ScalarField> {
    let mut hasher = Sha256::new();
    let mut uncompressed_bytes = Vec::new();
    x.serialize_uncompressed(&mut uncompressed_bytes)?;
    hasher.update(uncompressed_bytes);

    let mut uncompressed_bytes = Vec::new();
    y.serialize_uncompressed(&mut uncompressed_bytes)?;
    hasher.update(uncompressed_bytes);

    hasher.update(r);

    let hash_result = hasher.finalize();

    let hash_str = encode(hash_result);
    let hash_int = hex_to_bignum(&hash_str)?;
    let hash_ff: <C as Group>::ScalarField = hash_int.into();
    Ok(hash_ff)
}

pub fn hex_to_bignum(hex_str: &str) -> Result<BigUint, ParseBigIntError> {
    BigUint::from_str_radix(hex_str, 16)
}
