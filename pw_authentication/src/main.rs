
use ark_std::{rand::Rng, UniformRand};
use ark_ec::{CurveGroup, Group};
use ark_serialize::{CanonicalSerialize};
use sha2::{Digest, Sha256};
use hex::encode;
use num_bigint::{BigUint, ParseBigIntError};
use num_traits::Num;

const PW_SIZE :usize = 16;
const SALT_SIZE :usize = 16;


#[derive(Default, Debug)]
struct Proof<C : Group>{
    g: C,
    drand: String,
    commit: C,
    z: C::ScalarField,
}

#[derive(Debug,Clone)]
pub struct GroupDescription<C: CurveGroup> {
    pub generator: C,
}

impl < C : CurveGroup > GroupDescription<C>{
    fn setup() -> GroupDescription<C> {
        GroupDescription {
            generator: C::generator(),
        }
    }
    fn key_setup(self, pass_word : &[u8;PW_SIZE] ) -> (C::ScalarField , C){

        // Generate SALT
        let mut rng = rand::thread_rng();
        let mut salt = [0u8; SALT_SIZE];
        rng.fill(&mut salt);

        // Compute HASH
        let mut hasher = Sha256::new();
        let mut uncompressed_bytes = Vec::new();
        pass_word.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
        hasher.update(uncompressed_bytes);
        let mut uncompressed_bytes = Vec::new();
        salt.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
        hasher.update(uncompressed_bytes);
        let hash_result = hasher.finalize();
        //println!("result {:?}", hash_result);

        // HASH TO FIELD
        let hash_str = encode(hash_result);
        //println!("hash_str {}", hash_str);
        //let hash_int: u128 = u128::from_str_radix(&hash_str, 16).unwrap_or(0);
        let hash_int = hex_to_bignum(&hash_str).unwrap();
        //println!("hash_int {}", hash_int);
        let private_key : <C as Group>::ScalarField = hash_int.into();
        //println!("private_key {}", &private_key);

        // COMPUTE PUBLIC KEY
        let public_key = self.generator.mul(private_key);
        //println!("public_key {}", public_key);
        (private_key, public_key)
    }

     fn proof(self, publik_key : C , private_key : C::ScalarField)-> Proof<C>{
        let g = self.generator.clone();// ?

        let mut rng = ark_std::test_rng();
        //let w = <C as Group >::ScalarField::rand(&mut rng);
        //dbg!(w);
       // let h = self.generator.mul(&w);
        //dbg!(&h);

        let rand = <C as Group >::ScalarField::rand(&mut rng);
        let commit = C::generator().mul(&rand);


        let randomness = get_randomness().unwrap();
        let challenge = hash::<C> (&commit, &publik_key, &randomness);
        //dbg!(&e);
        //let e_f : <C as Group>::ScalarField  =  <<C as Group>::ScalarField>::from_le_bytes_mod_order(&challenge); use it for hash
        let z = private_key * challenge + rand;
        //dbg!(&z);

        Proof{
            g: g,
            drand: randomness,
            commit: commit,
            z: z,
        }
    }
    fn verify_proof(proof: &Proof<C>, public_key : &C)-> bool{
        //let e = hash::<C>( &proof.commit, &proof.g, &proof.h);
        let challenge = hash::<C> (&proof.commit, public_key, &proof.drand);
        //let e_f : <C as Group>::ScalarField  =  <<C as Group>::ScalarField>::from_le_bytes_mod_order(&e);
        let commit = proof.commit.clone();
        let lef_hand =  commit + (&public_key.mul(&challenge));
        let right_hand = proof.g.mul(&proof.z).clone();
        if lef_hand == right_hand {
            true
        }else{
            false
        }
    }
}

//fn generate_random_array<R: Rng>(rng : &mut R) -> [u8; PW_SIZE] {
fn generate_password() -> [u8; PW_SIZE] {
    //let mut rng = ark_std::test_rng();
    let mut rng = rand::thread_rng();
    let mut array = [0u8; PW_SIZE];
    rng.fill(&mut array);
    array
}



fn main() {

}


pub fn get_randomness() -> Result<String, String> {
    let randomness : String = "17281ff777148ec841fa6dd86c42ad049c04612f3948187a47fb0fe280f389fd".to_string() ;
    Ok(randomness)

}


pub fn hash< C: CurveGroup>(x :&C, y :&C, r : &String ) -> <C as Group>::ScalarField {//bit_vec::BitVec {
    let mut hasher = Sha256::new();
    let mut uncompressed_bytes = Vec::new();
    x.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    hasher.update(uncompressed_bytes);

    let mut uncompressed_bytes = Vec::new();
    y.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    hasher.update(uncompressed_bytes);

    hasher.update(r);

    let hash_result = hasher.finalize();

    let hash_str = encode(hash_result);
    //println!("hash_str {}", hash_str);
    //let hash_int: u128 = u128::from_str_radix(&hash_str, 16).unwrap_or(0);
    let hash_int = hex_to_bignum(&hash_str).unwrap();
    let hash_ff : <C as Group>::ScalarField = hash_int.into();
    return hash_ff;

}

pub fn hex_to_bignum(hex_str: &str) -> Result<BigUint, ParseBigIntError> {
    BigUint::from_str_radix(hex_str, 16)
}

#[cfg(test)]
mod test{
    use super::*;
    //use ark_ed_on_bn254::EdwardsProjective as tlcs_curve_bjj;
    use ark_ed_on_bn254::{EdwardsProjective as tlcs_curve_bjj, EdwardsAffine as affin_bjj,  Fr as Fr_tlcs_bjj, Fq as Fq_tlcs_bjj};
    use ark_secp256k1::{Fr as Fr_tlcs_secp, Projective as tlcs_curve_secp};
    use ark_bls12_381::{Fr as Fr_bls, G1Projective as tlcs_curve_bls};

    #[test]
    fn test_bjj_works() {
        for i in 0..10{
            let group_description : GroupDescription<tlcs_curve_bjj> =  GroupDescription::setup(); //Question: is there any other way to define this?
            let pw = generate_password();
            let (sk , pk ) = group_description.clone().key_setup(&pw);
            let proof : Proof<tlcs_curve_bjj> = group_description.proof(pk, sk);
            let vrf = GroupDescription::<tlcs_curve_bjj>::verify_proof(&proof, &pk);
            assert!(vrf);
        }
    }



    #[test]
    fn test_secp_works() {
        for i in 0..10{
            let group_description : GroupDescription<tlcs_curve_secp> =  GroupDescription::setup(); //Question: is there any other way to define this?
            let pw = generate_password();
            let (sk , pk ) = group_description.clone().key_setup(&pw);
            let proof : Proof<tlcs_curve_secp> = group_description.proof(pk, sk);
            let vrf = GroupDescription::<tlcs_curve_secp>::verify_proof(&proof, &pk);
            assert!(vrf);
        }
    }

    #[test]
    fn test_bls_works() {
        for i in 0..10{
            let group_description : GroupDescription<tlcs_curve_bls> =  GroupDescription::setup(); //Question: is there any other way to define this?
            let pw = generate_password();
            let (sk , pk ) = group_description.clone().key_setup(&pw);
            let proof : Proof<tlcs_curve_bls> = group_description.proof(pk, sk);
            let vrf = GroupDescription::<tlcs_curve_bls>::verify_proof(&proof, &pk);
            assert!(vrf);
        }
    }

}
