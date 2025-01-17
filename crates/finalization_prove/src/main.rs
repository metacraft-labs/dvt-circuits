#![no_main]

sp1_zkvm::entrypoint!(main);

use bls12_381::{
    G1Affine,
};

use bls_utils;

fn print_vec_g1_as_hex(v: Vec<G1Affine>) {
    for i in 0..v.len() {
        println!("{} ", hex::encode(v[i].to_compressed()));
    }
}

// fn verify_dvt(data: &AbiDvtData) -> Result<(), Box<dyn std::error::Error>> {
//     let verification_vectors: Vec<Vec<G1Affine>> = data.verification_vectors.iter().map(|vector| -> Vec<G1Affine> {
//         vector
//         .pubkeys
//         .iter()
//         .map(|pk: &[u8; 48]| G1Affine::from_compressed(&pk).into_option().unwrap())
//         .collect()
//     }).collect();

//     let mut all_pts = Vec::new();

//     print!("n = {}, k = {}\n", data.settings.n, data.settings.k);
//     print!("shares = {}, vectors = {}\n", data.shares.len(), verification_vectors.len());
//     for i in 0..data.shares.len() {
//         let mut pts = Vec::new();
//         let share_id = Scalar::from_bytes(&data.shares[i].id).unwrap();
//         for j in 0..verification_vectors.len() {
//             let pt = evaluate_polynomial(verification_vectors[j].clone(), share_id);
//             pts.push(pt);
//         }
//         all_pts.push(pts);
//     }

//     print_vec_g1_as_hex(verification_vectors[0].clone());

//     let mut final_keys =  Vec::new();

//     print!("{}: \n", all_pts.len());
//     for i in 0..all_pts.len() {
//         let mut key: G1Affine = all_pts[i][0];
//         print!("{}: \n", all_pts[i].len());
//         for j in 1..all_pts[i].len() {
//             key = G1Affine::from(G1Projective::from(key) + G1Projective::from(all_pts[i][j]));
//         }
//         final_keys.push(key);
//     }

//     print_vec_g1_as_hex(final_keys);

//     Ok(())
// }

// fn verify_dvt_from_aggregate(data: &AbiDvtData) -> Result<(), Box<dyn std::error::Error>> {
//     let verification_vectors: Vec<Vec<G1Affine>> = data.verification_vectors.iter().map(|vector| -> Vec<G1Affine> {
//         vector
//         .pubkeys
//         .iter()
//         .map(|pk: &[u8; 48]| G1Affine::from_compressed(&pk).into_option().unwrap())
//         .collect()
//     }).collect();

//     print!("n = {}, k = {}\n", data.settings.n, data.settings.k);
//     print!("shares = {}, vectors = {}\n", data.shares.len(), verification_vectors.len());
//     print_vec_g1_as_hex(verification_vectors[0].clone());

//     let mut final_keys =  Vec::new();
//     for i in 0..data.shares.len() {
//         let share_id = Scalar::from_bytes(&data.shares[i].id).unwrap();
//         println!("{} ", hex::encode(share_id.to_bytes()));
//         let pt = evaluate_polynomial(verification_vectors[0].clone(), share_id);
//         final_keys.push(pt);
//     }
//     print_vec_g1_as_hex(final_keys);

//     Ok(())
// }




pub fn main() {
    let data = bls_utils::read_finalization_data();
    let ok = bls_utils::verify_generations(&data.generations, &data.settings, &data.aggregate_pubkey);
    if ok.is_err() {
        panic!("{:?}", ok.unwrap_err().to_string());
    }

}


