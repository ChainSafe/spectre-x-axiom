use axiom_codec::constants::USER_INSTANCE_COLS;
use axiom_codec::types::native::{AxiomV2ComputeQuery, AxiomV2ComputeSnark};
use axiom_codec::utils::native::decode_hilo_to_h256;
use axiom_codec::HiLo;
use axiom_eth::halo2_proofs::halo2curves::bn256::Fr;
use axiom_eth::rlc::circuit::RlcCircuitParams;
use axiom_eth::snark_verifier::pcs::kzg::KzgDecidingKey;
use axiom_eth::snark_verifier_sdk::halo2::{gen_snark_shplonk, read_snark};
use axiom_eth::snark_verifier_sdk::{gen_pk, CircuitExt, Snark};
use axiom_eth::utils::build_utils::pinning::PinnableCircuit;
use axiom_eth::utils::snark_verifier::EnhancedSnark;
use axiom_query::components::results::types::{CircuitOutputResultsRoot, LogicOutputResultsRoot};
use axiom_query::verify_compute::types::{CircuitInputVerifyCompute, CoreParamsVerifyCompute};
use axiom_query::verify_compute::utils::{
    dummy_compute_circuit, get_metadata_from_protocol, get_onchain_vk_from_vk,
    reconstruct_snark_from_compute_query, write_onchain_vkey, UserCircuitParams,
    DEFAULT_CLIENT_METADATA, DEFAULT_USER_PARAMS,
};
use ethers_core::types::Bytes;
use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::halo2_proofs::plonk::Circuit;
use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2curves::bn256::Bn256;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn generate_snark<C: CircuitExt<Fr> + PinnableCircuit>(
    name: &'static str,
    params: &ParamsKZG<Bn256>,
    keygen_circuit: C,
    load_prover_circuit: &impl Fn(C::Pinning) -> C,
) -> anyhow::Result<EnhancedSnark> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let pinning_path = format!("{cargo_manifest_dir}/configs/test/{name}.json");
    let pk_path = format!("{cargo_manifest_dir}/data/test/{name}.pk");
    let (pk, pinning) = keygen_circuit.create_pk(params, pk_path, pinning_path)?;
    let vk = pk.get_vk();
    let mut vk_file = File::create(format!("data/test/{name}.vk"))?;
    vk.write(&mut vk_file, axiom_eth::halo2_proofs::SerdeFormat::RawBytes)?;
    let mut vk_file = File::create(format!("data/test/{name}.vk.txt"))?;
    write!(vk_file, "{:?}", vk.pinned())?;

    let component_circuit = load_prover_circuit(pinning);

    let snark_path = format!("data/test/{name}.snark");
    let snark = gen_snark_shplonk(params, &pk, component_circuit, Some(snark_path));
    Ok(EnhancedSnark { inner: snark, agg_vk_hash_idx: None })
}

#[derive(Clone, Debug, Serialize, Deserialize, Hash)]
#[serde(rename_all = "camelCase")]
pub struct InputVerifyCompute {
    pub source_chain_id: u64,
    pub subquery_results: LogicOutputResultsRoot,
    pub compute_query: AxiomV2ComputeQuery,
}

// Prepares input for `client_circuit` that is created with [BaseCircuitBuilder].
/// `client_circuit` is [BaseCircuitBuilder] populated with witnesses and fixed/copy constraints.
pub fn get_base_input(
    compute_name: &str,
    params: &ParamsKZG<Bn256>,
    max_outputs: usize,
    client_circuit: BaseCircuitBuilder<Fr>,
    subquery_results: LogicOutputResultsRoot,
    source_chain_id: u64,
    result_len: usize,
) -> anyhow::Result<InputVerifyCompute> {
    assert!(!client_circuit.witness_gen_only());
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let pk_path = format!("{cargo_manifest_dir}/data/test/{compute_name}.pk");
    let snark_path = format!("{cargo_manifest_dir}/data/test/{compute_name}.snark");

    let client_circuit_params = client_circuit.params();
    let pk = gen_pk(params, &client_circuit, Some(Path::new(&pk_path)));
    let compute_snark = gen_snark_shplonk(params, &pk, client_circuit, Some(snark_path));

    let client_metadata = get_metadata_from_protocol(
        &compute_snark.protocol,
        RlcCircuitParams { base: client_circuit_params, num_rlc_columns: 0 },
        max_outputs,
    )?;

    let onchain_vk = get_onchain_vk_from_vk(pk.get_vk(), client_metadata);
    let vkey = write_onchain_vkey(&onchain_vk)?;

    let instances = &compute_snark.instances;
    assert_eq!(instances.len(), USER_INSTANCE_COLS);
    let instances = &instances[0];
    let compute_results = instances
        .iter()
        .chunks(2)
        .into_iter()
        .take(result_len)
        .map(|hilo| {
            let hilo = hilo.collect_vec();
            assert_eq!(hilo.len(), 2);
            decode_hilo_to_h256(HiLo::from_hi_lo([*hilo[0], *hilo[1]]))
        })
        .collect();
    let compute_snark = AxiomV2ComputeSnark {
        kzg_accumulator: None,
        compute_results,
        proof_transcript: compute_snark.proof,
    };
    let compute_proof = Bytes::from(compute_snark.encode().unwrap());
    let compute_query = AxiomV2ComputeQuery {
        k: params.k() as u8,
        result_len: result_len as u16,
        vkey,
        compute_proof,
    };
    Ok(InputVerifyCompute { source_chain_id, subquery_results, compute_query })
}

/// **Assumptions:**
/// - The generator `params_for_dummy.get_g()[0]` should match that of the trusted setup used to generate `input.compute_query` if there is a compute query.
/// - If there is no compute query (so compute_query.k == 0), then a dummy compute snark is generated using `params_for_dummy` with [DEFAULT_CLIENT_METADATA].
pub fn reconstruct_verify_compute_circuit(
    input: InputVerifyCompute,
    params_for_dummy: &ParamsKZG<Bn256>,
) -> anyhow::Result<(CoreParamsVerifyCompute, CircuitInputVerifyCompute)> {
    let InputVerifyCompute { source_chain_id, subquery_results, compute_query } = input;

    let compute_query_result_len = compute_query.result_len;
    let nonempty_compute_query = compute_query.k != 0;
    let (compute_snark, client_metadata) = if compute_query.k == 0 {
        (default_compute_snark(params_for_dummy), DEFAULT_CLIENT_METADATA.clone())
    } else {
        reconstruct_snark_from_compute_query(subquery_results.clone(), compute_query)?
    };
    let subquery_results = CircuitOutputResultsRoot::try_from(subquery_results)?;
    let circuit_params = CoreParamsVerifyCompute::new(
        subquery_results.results.len(),
        params_for_dummy.get_g()[0],
        client_metadata,
        compute_snark.protocol.preprocessed.len(),
    );
    println!("compute_snark.protocol.preprocessed.len(): {}", circuit_params.preprocessed_len());

    Ok((
        circuit_params,
        CircuitInputVerifyCompute::new(
            source_chain_id,
            subquery_results,
            nonempty_compute_query,
            compute_query_result_len,
            compute_snark,
        ),
    ))
}

/// Create a dummy snark that **will verify** successfully.
pub fn dummy_compute_snark(
    kzg_params: &ParamsKZG<Bn256>,
    user_params: UserCircuitParams,
    cache_dir: impl AsRef<Path>,
) -> Snark {
    // tag for caching the dummy
    let tag = {
        // UserCircuitParams and KzgDecidingKey are enough to tag the dummy snark; we don't need `k`
        let mut hasher = blake3::Hasher::new();
        hasher.update(&serde_json::to_vec(&user_params).unwrap());
        // hash num instance in case we change the format
        hasher.update(&user_params.num_instances().to_be_bytes());
        let dk: KzgDecidingKey<Bn256> =
            (kzg_params.get_g()[0], kzg_params.g2(), kzg_params.s_g2()).into();
        hasher.update(&serde_json::to_vec(&dk).unwrap());
        let id = hasher.finalize();
        cache_dir.as_ref().join(format!("{id}.snark"))
    };
    if let Ok(snark) = read_snark(&tag) {
        return snark;
    }
    let circuit = dummy_compute_circuit(user_params, kzg_params.k());
    let pk = gen_pk(kzg_params, &circuit, None);
    gen_snark_shplonk(kzg_params, &pk, circuit, Some(tag))
}

pub fn default_compute_snark(params: &ParamsKZG<Bn256>) -> Snark {
    let mut cache_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    cache_dir.push("data");
    cache_dir.push("default_compute_snark");
    std::fs::create_dir_all(&cache_dir).unwrap();
    dummy_compute_snark(params, DEFAULT_USER_PARAMS, &cache_dir)
}
