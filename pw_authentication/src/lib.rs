mod primitives;
use primitives::*;

use ark_ff::{BigInteger, Field, PrimeField,One};
use ark_std::{rand::Rng, UniformRand};
use ark_bls12_381::{Fr, G1Projective as Projective};
use ark_ec::{AffineRepr, CurveGroup, Group};
use std::ops::Mul;


#[derive(Debug,Clone)]
pub struct Group_Description<C: CurveGroup> {
    pub generator: C,
}

#[derive(Default, Debug)]
struct Proof<C : Group>{
    g: C,
    h: C,
    commit: C,
    z: C::ScalarField,
}
impl <C: CurveGroup> Proof<C> {
    fn setup()-> Group_Description<C>{
        Group_Description{
            generator: C::generator(),
        }
    }
    fn generate_proof(group_description: &Group_Description<C>)-> Proof<C>{
        let g = group_description.generator.clone();// ?

        let mut rng = ark_std::test_rng();
        let w = <C as Group >::ScalarField::rand(&mut rng);
        //dbg!(w);
        let h = group_description.generator.mul(&w);
        //dbg!(&h);

        let rand = <C as Group >::ScalarField::rand(&mut rng);
        let commit = C::generator().mul(&rand);
        let e = hash::<C> ( &commit, &(group_description.generator), &h);
        //dbg!(&e);
        let e_f : <C as Group>::ScalarField  =  <<C as Group>::ScalarField>::from_le_bytes_mod_order(&e);
        let z = e_f * w + rand;
        //dbg!(&z);

        Proof{
            g: g,
            h: h,
            commit: commit,
            z: z,
        }
    }
    fn verify_proof(proof: &Proof<C>)-> bool{
        let e = hash::<C>( &proof.commit, &proof.g, &proof.h);
        let e_f : <C as Group>::ScalarField  =  <<C as Group>::ScalarField>::from_le_bytes_mod_order(&e);
        let commit = proof.commit.clone();
        let lef_hand =  commit + (&proof.h.mul(&e_f));
        let right_hand = proof.g.mul(&proof.z).clone();
        if lef_hand == right_hand {
            true
        }else{
            false
        }
    }
}
#[test]
fn sigma_prot_test() {
    let group_description : Group_Description<Projective> =  Proof::setup(); //Question: is there any other way to define this?
    let mut proof :Proof<Projective>;
    proof = Proof::generate_proof(&group_description);
    let result = Proof::verify_proof(&proof);
    println!("result = {}",result);
}
