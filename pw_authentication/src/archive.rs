mod primitives;
mod sigma_prot;

use primitives::*;
use sigma_prot::*;

use ark_ff::{BigInteger, Field, PrimeField,One};
use ark_std::{rand::Rng, UniformRand};
use ark_bls12_381::{Fr, G1Projective as Projective};
use ark_ec::{AffineRepr, CurveGroup, Group};
use std::ops::Mul;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use sha2::{Digest, Sha256};
use hex::encode;
use num_bigint::{BigUint, ParseBigIntError};
use num_integer::Integer;
use num_traits::Num;
use ark_ec::pairing::Pairing;



use ark_std::Zero;

const PW_SIZE :usize = 16;

#[derive(Debug,Clone)]
pub struct Group_Description<C: CurveGroup> {
    pub generator: C,
}

impl <C : CurveGroup> Group_Description<C: CurveGroup>{
    fn key_setup(pass_word : &[u8;PW_SIZE] ) -> (C::ScalarField , C){

    }

}

#[derive(Default, Debug)]
struct Proof<C : Group>{
    g: C,
    h: C,
    commit: C,
    z: C::ScalarField,
}
impl <C: CurveGroup> Proof<C> {
    fn setup() -> Group_Description<C> {
        Group_Description {
            generator: C::generator(),
        }
    }
    fn generate_proof(group_description: &Group_Description<C>) -> Proof<C> {
        let g = group_description.generator.clone();// ?

        let mut rng = ark_std::test_rng();
        let w = <C as Group>::ScalarField::rand(&mut rng);
        //dbg!(w);
        let h = group_description.generator.mul(&w);
        //dbg!(&h);

        let rand = <C as Group>::ScalarField::rand(&mut rng);
        let commit = C::generator().mul(&rand);
        let e = hash::<C>(&commit, &(group_description.generator), &h);
        //dbg!(&e);
        let e_f: <C as Group>::ScalarField = <<C as Group>::ScalarField>::from_le_bytes_mod_order(&e);
        let z = e_f * w + rand;
        //dbg!(&z);

        Proof {
            g: g,
            h: h,
            commit: commit,
            z: z,
        }
    }
    fn verify_proof(proof: &Proof<C>) -> bool {
        let e = hash::<C>(&proof.commit, &proof.g, &proof.h);
        let e_f: <C as Group>::ScalarField = <<C as Group>::ScalarField>::from_le_bytes_mod_order(&e);
        let commit = proof.commit.clone();
        let lef_hand = commit + (&proof.h.mul(&e_f));
        let right_hand = proof.g.mul(&proof.z).clone();
        if lef_hand == right_hand {
            true
        } else {
            false
        }
    }
}
/*
fn password_generation<C: Group>(user_id : Vec<u8>) -> (C, C::ScalarField){
let mut rng = ark_std::test_rng();
let sk = <C as Group >::ScalarField::rand(&mut rng);
let salt = <C as Group >::ScalarField::rand(&mut rng);


}

*/
/*
let mut hasher = Sha256::new();
let mut uncompressed_bytes = Vec::new();
pw.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
hasher.update(uncompressed_bytes);

let mut uncompressed_bytes = Vec::new();
salt.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
hasher.update(uncompressed_bytes);

let result = hasher.finalize();
result.to_vec();


 */
pub fn hex_to_bignum(hex_str: &str) -> Result<BigUint, ParseBigIntError> {
    BigUint::from_str_radix(hex_str, 16)
}

//fn generate_random_array<R: Rng>(rng : &mut R) -> [u8; PW_SIZE] {
fn generate_random_array() -> [u8; PW_SIZE] {
    //let mut rng = ark_std::test_rng();
    let mut rng = rand::thread_rng();
    let mut array = [0u8; PW_SIZE];
    rng.fill(&mut array);
    array
}

fn main() {
    let group_description : Group_Description<Projective> =  Proof::setup(); //Question: is there any other way to define this?
    //  let mut rng = ark_std::test_rng();
    let mut rng = rand::thread_rng();
    let pw = generate_random_array();
    let salt = generate_random_array();
    //let mut proof :Proof<Projective>;
    //proof = Proof::generate_proof(&group_description);
    //let result = Proof::verify_proof(&proof);
    //println!("result = {}",result);

    let test_arr = generate_random_array();
    println!("sk {:?}", pw);
    println!("salt {:?}", salt);

    let mut hasher = Sha256::new();
    let mut uncompressed_bytes = Vec::new();
    pw.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    hasher.update(uncompressed_bytes);

    let mut uncompressed_bytes = Vec::new();
    salt.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    hasher.update(uncompressed_bytes);

    let result = hasher.finalize();
    println!("result {:?}", result);
    //result.to_vec();
    //println!("result {:?}", result);

    // Convert the hash to a u64 integer
    let hash_str = encode(result);
    println!("hash_str {}", hash_str);
    //let hash_int: u128 = u128::from_str_radix(&hash_str, 16).unwrap_or(0);
    let hash_int = hex_to_bignum(&hash_str).unwrap();
    println!("hash_int {}", hash_int);
    let private_key : <Projective as Group>::ScalarField = hash_int.into();
    println!("private_key {}", private_key);
    let public_key = group_description.generator.mul(private_key);
    println!("public_key {}", public_key);




    // Map the hash to the finite field modulus
    //hash_int % MODULUS
}
