use anyhow::Result;
use ark_ec::{CurveGroup, Group};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use hex::encode;
use num_bigint::{BigUint, ParseBigIntError};
use num_traits::Num;
use sha3::{Digest, Sha3_256 as HashFunc};

#[derive(Default, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub struct Proof<C: Group> {
    pub g: C, // maybe it's extra field. I think we can use enum and construct it on the fly.
    /// Random value from which calculates commit and z.
    pub rand: String,
    pub commit: C,
    pub z: C::ScalarField,
}

#[derive(Debug, Default, Clone)]
pub struct GroupDescription<C: CurveGroup> {
    generator: C,
}

impl<C: CurveGroup> GroupDescription<C> {
    /// Constructor of the instance.
    pub fn new() -> GroupDescription<C> {
        GroupDescription {
            generator: C::generator(),
        }
    }

    /// A helper routine that generate keypair at once.
    pub fn generate_keypair<S: AsRef<[u8]>>(
        &self,
        pass_word: S,
        salt: &[u8],
    ) -> Result<(C::ScalarField, C)> {
        let private_key = self.generate_private_key(salt, pass_word.as_ref())?;
        let public_key = self.generate_public_key(&private_key);
        Ok((private_key, public_key))
    }

    /// Allow user to generate own private_key from given password and salt.
    pub fn generate_private_key<S: AsRef<[u8]>>(
        &self,
        pass_word: S,
        salt: &[u8],
    ) -> Result<C::ScalarField> {
        // Compute HASH
        let mut hasher = HashFunc::new();
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
        Ok(private_key)
    }

    /// Generate public key from a private.
    pub fn generate_public_key(&self, private_key: &C::ScalarField) -> C {
        self.generator.mul(private_key)
    }

    /// Generate proof from given random value.
    pub fn proof<S: AsRef<str>>(
        &self,
        publik_key: C,
        private_key: C::ScalarField,
        randomness: S,
    ) -> Result<Proof<C>> {
        let mut rng = ark_std::rand::thread_rng();

        let rand = <C as Group>::ScalarField::rand(&mut rng);
        let commit = C::generator().mul(&rand);

        let randomness = randomness.as_ref();
        let challenge = hash::<C>(&commit, &publik_key, randomness)?;
        let z = private_key * challenge + rand;

        Ok(Proof {
            g: self.generator,
            rand: randomness.to_string(),
            commit,
            z,
        })
    }

    /// Verifies given proof using public key.
    pub fn verify_proof(proof: &Proof<C>, public_key: &C) -> bool {
        let challenge =
            hash::<C>(&proof.commit, public_key, &proof.rand).expect("Expected correct hashing");
        let commit = proof.commit;
        let lef_hand = commit + (public_key.mul(&challenge));
        let right_hand = proof.g.mul(&proof.z);
        lef_hand == right_hand
    }
}

fn hash<C: CurveGroup>(x: &C, y: &C, r: &str) -> Result<<C as Group>::ScalarField> {
    let mut hasher = HashFunc::new();
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

fn hex_to_bignum(hex_str: &str) -> Result<BigUint, ParseBigIntError> {
    BigUint::from_str_radix(hex_str, 16)
}
