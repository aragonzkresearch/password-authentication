fn main() {}

#[cfg(test)]
mod test {
    use ark_bls12_381::G1Projective as tlcs_curve_bls;
    use ark_ed_on_bn254::EdwardsProjective as tlcs_curve_bjj;
    use ark_secp256k1::Projective as tlcs_curve_secp;
    use ark_std::rand::Rng;
    use pw_authentication::*;

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
            let group_description: GroupDescription<tlcs_curve_bjj> = GroupDescription::new(); //Question: is there any other way to define this?
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
            let group_description: GroupDescription<tlcs_curve_secp> = GroupDescription::new(); //Question: is there any other way to define this?
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
            let group_description: GroupDescription<tlcs_curve_bls> = GroupDescription::new(); //Question: is there any other way to define this?
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
