use ark_bn254::Bn254;
use ark_groth16::{r1cs_to_qap::LibsnarkReduction, Groth16};
use lazy_static::lazy_static;
use zkm2_sdk::{include_elf, utils, HashableKey, ProverClient, ZKMProofWithPublicValues, ZKMStdin};
use zkm2_verifier::{
    decode_zkm2_vkey_hash, hash_public_inputs, load_ark_groth16_verifying_key_from_bytes,
    load_ark_proof_from_bytes, load_ark_public_inputs_from_bytes,
};

/// The ELF we want to execute inside the zkVM.
const ELF: &[u8] = include_elf!("fibonacci");

lazy_static! {
    /// The Groth16 verifying key for this ZKM2 version.
    pub static ref GROTH16_VK_BYTES: &'static [u8] = include_bytes!("../bin/groth16_vk.bin");
}

#[test]
fn test_zkm2_groth16() {
    // Setup logging.
    utils::setup_logger();

    // Create an input stream and write '10' to it.
    let n = 10u32;

    let mut stdin = ZKMStdin::new();
    stdin.write(&n);

    // Set up the pk and vk.
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);

    // Generate the Groth16 proof.
    let proof = client.prove(&pk, stdin).groth16().run().unwrap();
    println!("generated proof");

    // Get the public values as bytes.
    let public_values = proof.public_values.as_slice();
    println!("public values: 0x{}", hex::encode(public_values));

    // Get the proof as bytes.
    let solidity_proof = proof.bytes();
    println!("proof: 0x{}", hex::encode(solidity_proof));

    // Verify proof and public values
    client.verify(&proof, &vk).expect("verification failed");

    // Save the proof.
    proof.save("fibonacci-groth16.bin").expect("saving proof failed");

    // groth16 vk: ~/.zkm2/circuits/dev/groth16_vk.bin

    println!("successfully generated and verified proof for the program!");
    println!("vk: {:?}", vk.bytes32());
}

#[test]
fn test_zkm2_verify_ark_groth16() {
    // Location of the serialized ZKMProofWithPublicValues. See README.md for more information.
    let proof_file = "bin/fibonacci-groth16.bin";

    // Load the saved proof and extract the proof and public inputs.
    let zkm2_proof_with_public_values = ZKMProofWithPublicValues::load(proof_file).unwrap();

    let proof = zkm2_proof_with_public_values.bytes();
    let public_inputs = zkm2_proof_with_public_values.public_values.to_vec();

    println!("proof: {:?}\n", proof);
    println!("public_inputs: {:?}\n", public_inputs);

    // This vkey hash was derived by calling `vk.bytes32()` on the verifying key.
    let vkey_hash = "0x0008f3156596bab55d59f3e5e93e5793f34e10aba7460dc91fe90d8e08b4cef8";

    // Convert gnark proof to arkworks proof
    let ark_proof = load_ark_proof_from_bytes(&proof[4..]).unwrap();
    let ark_vkey = load_ark_groth16_verifying_key_from_bytes(&GROTH16_VK_BYTES).unwrap();
    let ark_public_inputs = load_ark_public_inputs_from_bytes(
        &decode_zkm2_vkey_hash(&vkey_hash).unwrap(),
        &hash_public_inputs(&public_inputs),
    );
    println!("ark_proof: {:?}\n", ark_proof);
    println!("ark_public_inputs: {:?}\n", ark_public_inputs);

    // verify proof
    let ok = Groth16::<Bn254, LibsnarkReduction>::verify_proof(&ark_vkey.into(), &ark_proof, &ark_public_inputs)
    .unwrap();
    assert!(ok);
}
