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
    /// Generic generator that can be reused in destination handler.
    pub g: C,
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
    pub fn new(generator: C) -> GroupDescription<C> {
        GroupDescription { generator }
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

#[cfg(test)]
mod test {
    use super::*;
    use ark_bls12_381::G1Projective as tlcs_curve_bls;
    use ark_ed_on_bn254::EdwardsProjective as tlcs_curve_bjj;
    use ark_secp256k1::Projective as tlcs_curve_secp;
    use ark_std::rand::Rng;

    const PW_SIZE: usize = 16;
    const SALT_SIZE: usize = 16;

    fn generate_password() -> [u8; PW_SIZE] {
        let mut rng = rand::thread_rng();
        let mut array = [0u8; PW_SIZE];
        rng.fill(&mut array);
        array
    }

    fn generate_random_salt() -> [u8; SALT_SIZE] {
        // Generate SALT
        let mut rng = rand::thread_rng();
        let mut salt = [0u8; SALT_SIZE];
        rng.fill(&mut salt);
        salt
    }

    pub fn get_randomness() -> &'static str {
        "17281ff777148ec841fa6dd86c42ad049c04612f3948187a47fb0fe280f389fd"
    }

    #[test]
    fn test_bjj_works() {
        for _i in 0..10 {
            let g = tlcs_curve_bjj::generator();
            let group_description = GroupDescription::new(g); //Question: is there any other way to define this?
            let pw = generate_password();
            let salt = generate_random_salt();
            let (sk, pk) = group_description
                .clone()
                .generate_keypair(&pw, &salt)
                .unwrap();
            let proof: Proof<tlcs_curve_bjj> =
                group_description.proof(pk, sk, get_randomness()).unwrap();
            let vrf = GroupDescription::<tlcs_curve_bjj>::verify_proof(&proof, &pk);
            assert!(vrf);
        }
    }

    #[test]
    fn test_secp_works() {
        for _i in 0..10 {
            let g = tlcs_curve_secp::generator();
            let group_description = GroupDescription::new(g); //Question: is there any other way to define this?
            let pw = generate_password();
            let salt = generate_random_salt();
            let (sk, pk) = group_description
                .clone()
                .generate_keypair(&pw, &salt)
                .unwrap();
            let proof: Proof<tlcs_curve_secp> =
                group_description.proof(pk, sk, get_randomness()).unwrap();
            let vrf = GroupDescription::<tlcs_curve_secp>::verify_proof(&proof, &pk);
            assert!(vrf);
        }
    }

    #[test]
    fn test_bls_works() {
        for _i in 0..10 {
            let g = tlcs_curve_bls::generator();
            let group_description = GroupDescription::new(g); //Question: is there any other way to define this?
            let pw = generate_password();
            let salt = generate_random_salt();
            let (sk, pk) = group_description
                .clone()
                .generate_keypair(&pw, &salt)
                .unwrap();
            let proof: Proof<tlcs_curve_bls> =
                group_description.proof(pk, sk, get_randomness()).unwrap();
            let vrf = GroupDescription::<tlcs_curve_bls>::verify_proof(&proof, &pk);
            assert!(vrf);
        }
    }
}
