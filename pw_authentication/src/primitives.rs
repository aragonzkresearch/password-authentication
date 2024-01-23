use ark_ff::{BigInteger, Field, PrimeField,One};
use ark_std::{rand::Rng, UniformRand};
//use ark_bls12_381::{Fr, G1Projective as Projective};
use ark_ec::{AffineRepr, CurveGroup, Group};
//use std::sync::Arc;
//use ark_ff::Fp;
//use bit_vec::BitVec;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use std::ops::Mul;
use sha2::{Digest, Sha256};

pub fn field_to_byte<F: Field>( f: &F) ->Vec<u8>{
    let mut f_bytes = Vec::new();
    f.serialize_uncompressed(&mut f_bytes).unwrap();
    return f_bytes;
}

pub fn hash< C: CurveGroup>(x :&C ,y :&C,z :&C) -> Vec<u8>{//bit_vec::BitVec {
    let mut hasher = Sha256::new();

    let mut uncompressed_bytes = Vec::new();
    x.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    hasher.update(uncompressed_bytes);

    let mut uncompressed_bytes = Vec::new();
    y.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    hasher.update(uncompressed_bytes);

    let mut uncompressed_bytes = Vec::new();
    z.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    hasher.update(uncompressed_bytes);

    let result = hasher.finalize();
    result.to_vec()

}

pub fn group_gen<G : Group>() -> G {
    //let mut rng = rand::thread_rng(); //Real application
    let mut rng = ark_std::test_rng(); //Test version
    G::rand(&mut rng)
}

fn field_rng_gen<F: Field>() -> F{
    //let mut rng = rand::thread_rng(); //Real application
    let mut rng = ark_std::test_rng(); //Test version
    F::rand(&mut rng)
}