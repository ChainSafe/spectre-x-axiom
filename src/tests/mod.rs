mod utils;
use std::{
    collections::HashMap,
    fs::{self, File},
    marker::PhantomData,
    path::Path,
    result,
    str::FromStr,
};

use crate::beacon_header::{
    circuit::ComponentCircuitBeaconSubquery,
    types::{ComponentTypeBeaconSubquery, CoreParamsBeaconSubquery, OutputBeaconShard},
};
use crate::utils::witness::fetch_beacon_args;
use axiom_codec::{
    constants::{NUM_SUBQUERY_TYPES, USER_MAX_OUTPUTS},
    types::{
        field_elements::{AnySubqueryResult, FieldSubqueryResult, SUBQUERY_KEY_LEN},
        native::{AccountSubquery, HeaderSubquery, StorageSubquery, SubqueryResult, SubqueryType},
    },
    utils::native::u256_to_h256,
};
use axiom_eth::utils::{
    build_utils::pinning::{PinnableCircuit, RlcCircuitPinning},
    snark_verifier,
};
use axiom_eth::{
    block_header::STATE_ROOT_INDEX,
    halo2_proofs::halo2curves::bn256::Fr,
    keccak::{
        promise::generate_keccak_shards_from_calls,
        types::{ComponentTypeKeccak, OutputKeccakShard},
    },
    providers::{setup_provider, storage::json_to_mpt_input},
    snark_verifier_sdk::{gen_pk, halo2::gen_snark_shplonk, CircuitExt},
    utils::{
        component::{
            promise_loader::{
                comp_loader::SingleComponentLoaderParams, multi::MultiPromiseLoaderParams,
                single::PromiseLoaderParams,
            },
            ComponentCircuit, ComponentPromiseResultsInMerkle, ComponentType,
            GroupedPromiseResults,
        },
        merkle_aggregation::InputMerkleAggregation,
        snark_verifier::{AggregationCircuitParams, EnhancedSnark},
    },
};
use axiom_query::{
    axiom_aggregation1::types::InputAxiomAggregation1,
    components::{
        dummy_rlc_circuit_params,
        results::{
            circuit::{ComponentCircuitResultsRoot, CoreParamsResultRoot},
            table::SubqueryResultsTable,
            types::{CircuitInputResultsRootShard, LogicOutputResultsRoot},
        },
        subqueries::{
            account::{
                circuit::{ComponentCircuitAccountSubquery, CoreParamsAccountSubquery},
                types::{
                    CircuitInputAccountShard, CircuitInputAccountSubquery,
                    ComponentTypeAccountSubquery, OutputAccountShard,
                },
                STORAGE_ROOT_INDEX,
            },
            common::shard_into_component_promise_results,
            storage::{
                circuit::{ComponentCircuitStorageSubquery, CoreParamsStorageSubquery},
                types::{
                    CircuitInputStorageShard, CircuitInputStorageSubquery,
                    ComponentTypeStorageSubquery, OutputStorageShard,
                },
            },
        },
    },
    subquery_aggregation::types::{InputSubqueryAggregation, SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX},
    verify_compute::{
        circuit::ComponentCircuitVerifyCompute,
        types::CircuitInputVerifyCompute,
        utils::{default_compute_circuit, UserCircuitParams, DEFAULT_USER_PARAMS},
    },
};
use ethers_core::types::{Address, Bytes, Chain, H256, U256};
use ethers_providers::Middleware;
use futures::future::join_all;
use halo2_base::{
    gates::circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, CircuitBuilderStage},
    halo2_proofs::{
        dev::MockProver,
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    },
    utils::fs::gen_srs,
};
use halo2curves::{bn256::Bn256, ff::Field};
use itertools::Itertools;
use std::io::Write;
use url::Url;
use utils::generate_snark;
use zkevm_hashes::keccak::component::{
    circuit::shard::{KeccakComponentShardCircuit, KeccakComponentShardCircuitParams},
    output,
};

use self::utils::reconstruct_verify_compute_circuit;

pub const ACCOUNT_PROOF_MAX_DEPTH: usize = 13;
pub const STORAGE_PROOF_MAX_DEPTH: usize = 13;

pub const KECCAK_F_CAPACITY: usize = 100;

#[tokio::test]
async fn test_beacon_query_e2e() {
    let _ = env_logger::builder().is_test(true).try_init();
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    fs::create_dir_all(format!("{cargo_manifest_dir}/configs/test")).unwrap();
    fs::create_dir_all(format!("{cargo_manifest_dir}/data/test")).unwrap();

    let mut subquery_results = vec![];
    let mut promise_results = HashMap::new();
    let mut keccak_witnesses = vec![];

    let params_header = gen_srs(20);
    let params = gen_srs(19);

    let gen_snark_header =
        generate_header_snark(&params_header, &mut promise_results).await.unwrap();

    let gen_snark_account = generate_account_snark(
        &params,
        Chain::Mainnet,
        vec![(19149117, "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", STORAGE_ROOT_INDEX)],
        &mut subquery_results,
        &mut promise_results,
        &mut keccak_witnesses,
    )
    .await
    .unwrap();

    let gen_snark_storage = generate_storage_snark(
        &params,
        Chain::Mainnet,
        vec![(19149117, "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", H256::zero())],
        &mut subquery_results,
        &mut promise_results,
        &mut keccak_witnesses,
    )
    .await
    .unwrap();

    let compute_params = gen_srs(14);

    let gen_snark_verify_compute = generate_verify_compute(
        "compute_for_agg",
        &compute_params,
        &params,
        subquery_results.clone(),
        &mut keccak_witnesses,
        Chain::Mainnet.into(),
    )
    .unwrap();

    let snark_results_root = generate_results_snark(
        &params,
        &mut promise_results,
        subquery_results,
        &mut keccak_witnesses,
    )
    .unwrap();

    // Calculate final keccak promice out of all keccak queries used in prev circuits
    let keccak_shard =
        OutputKeccakShard { responses: keccak_witnesses.clone(), capacity: KECCAK_F_CAPACITY };
    let keccak_merkle = ComponentPromiseResultsInMerkle::<Fr>::from_single_shard(
        keccak_shard.clone().into_logical_results(),
    );
    promise_results.insert(ComponentTypeKeccak::<Fr>::get_type_id(), keccak_merkle);
    let promise_commit_keccak =
        promise_results.get(&ComponentTypeKeccak::<Fr>::get_type_id()).unwrap().leaves()[0].commit;

    let snark_header = gen_snark_header(&params_header, &promise_results).unwrap();
    let snark_account = gen_snark_account(&params, &promise_results).unwrap();
    let snark_storage = gen_snark_storage(&params, &promise_results).unwrap();
    let snark_verify_compute = gen_snark_verify_compute(&params, &promise_results).unwrap();

    let aggregation_payload = InputSubqueryAggregation {
        snark_header,
        snark_results_root,
        snark_account: Some(snark_account),
        snark_storage: Some(snark_storage),
        snark_solidity_mapping: None,
        snark_tx: None,
        snark_receipt: None,
        promise_commit_keccak,
    };

    let agg_params = params_header;

    let mut keygen_circuit = aggregation_payload
        .clone()
        .build(
            CircuitBuilderStage::Keygen,
            AggregationCircuitParams {
                degree: params.k(),
                lookup_bits: (params.k() as usize) - 1,
                ..Default::default()
            },
            &params,
        )
        .unwrap();
    keygen_circuit.calculate_params(Some(20));

    let mut snark_subquery_agg =
        generate_snark("subquery_aggregation_for_agg", &agg_params, keygen_circuit, &|pinning| {
            aggregation_payload.clone().prover_circuit(pinning, &params).unwrap()
        })
        .unwrap();
    snark_subquery_agg.agg_vk_hash_idx = Some(SUBQUERY_AGGREGATION_AGG_VKEY_HASH_IDX);

    let snark_keccak_agg = gen_keccak_snark(&params, &agg_params, keccak_shard).unwrap();

    let agg1_input =
        InputAxiomAggregation1 { snark_verify_compute, snark_subquery_agg, snark_keccak_agg };
    let agg1_params = agg_params; //gen_srs(22);
    let mut keygen_circuit = agg1_input
        .clone()
        .build(
            CircuitBuilderStage::Mock,
            AggregationCircuitParams {
                degree: agg1_params.k(),
                lookup_bits: (agg1_params.k() as usize) - 1,
                ..Default::default()
            },
            &agg1_params,
        )
        .unwrap();
    keygen_circuit.calculate_params(Some(20));

    MockProver::run(agg1_params.k(), &keygen_circuit, keygen_circuit.instances())
        .unwrap()
        .assert_satisfied();

    // let _ = generate_snark("axiom_aggregation1", &agg1_params, keygen_circuit, &|pinning| {
    //     agg1_input.clone().prover_circuit(pinning, &agg1_params).unwrap()
    // }).unwrap();
}

async fn generate_header_snark(
    params: &ParamsKZG<Bn256>,
    promise_results: &mut GroupedPromiseResults<Fr>,
) -> anyhow::Result<
    impl FnOnce(&ParamsKZG<Bn256>, &GroupedPromiseResults<Fr>) -> anyhow::Result<EnhancedSnark>,
> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");

    let client = beacon_api_client::mainnet::Client::new(
        Url::parse("https://lodestar-mainnet.chainsafe.io").unwrap(),
    );

    let beacon_input =
        match File::open(format!("{cargo_manifest_dir}/data/test/input_beacon_for_agg.json")) {
            Err(_) => {
                let beacon_input = fetch_beacon_args(&client).await.unwrap();
                let file = File::create(format!(
                    "{cargo_manifest_dir}/data/test/input_beacon_for_agg.json"
                ))?;
                serde_json::to_writer(file, &beacon_input)?;
                beacon_input
            }
            Ok(file) => serde_json::from_reader(file).unwrap(),
        };

    // let (header_core_params, header_promise_params, header_base_params) = read_beacon_pinning()?;
    let circuit_params = BaseCircuitParams {
        k: params.k() as usize,
        lookup_bits: Some(params.k() as usize - 1),
        num_instance_columns: 1,
        ..Default::default()
    };

    let mut beacon_circuit = ComponentCircuitBeaconSubquery::<Fr>::new(
        CoreParamsBeaconSubquery { capacity: 1 },
        // PromiseLoaderParams { comp_loader_params: SingleComponentLoaderParams::new(0, vec![0]) },
        (),
        circuit_params,
    );
    beacon_circuit.feed_input(Box::new(beacon_input.clone())).unwrap();
    beacon_circuit.fulfill_promise_results(promise_results).unwrap();
    beacon_circuit.calculate_params();

    Ok(move |params: &ParamsKZG<Bn256>, promise_results: &GroupedPromiseResults<Fr>| {
        generate_snark("beacon_subquery_for_agg", params, beacon_circuit, &|pinning| {
            let circuit = ComponentCircuitBeaconSubquery::<Fr>::prover(
                CoreParamsBeaconSubquery { capacity: 1 },
                // PromiseLoaderParams {
                //     comp_loader_params: SingleComponentLoaderParams::new(0, vec![0]),
                // },
                (),
                pinning,
            );
            circuit.feed_input(Box::new(beacon_input.clone())).unwrap();
            circuit.fulfill_promise_results(promise_results).unwrap();
            circuit
        })
    })
}

async fn generate_account_snark(
    params: &ParamsKZG<Bn256>,
    network: Chain,
    subqueries: Vec<(u64, &str, usize)>, // (blockNum, addr, fieldIdx)
    subquery_results: &mut Vec<SubqueryResult>,
    promise_results: &mut GroupedPromiseResults<Fr>,
    keccak_witnesses: &mut Vec<(Bytes, Option<H256>)>,
) -> anyhow::Result<
    impl FnOnce(&ParamsKZG<Bn256>, &GroupedPromiseResults<Fr>) -> anyhow::Result<EnhancedSnark>,
> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");

    let k = params.k();

    let _provider = setup_provider(network);
    let provider = &_provider;

    let requests =
        match File::open(format!("{cargo_manifest_dir}/data/test/input_account_for_agg.json")) {
            Err(_) => {
                let results = join_all(subqueries.into_iter().map(
                    |(block_num, addr, field_idx)| async move {
                        let addr = Address::from_str(addr).unwrap();
                        let block = provider.get_block(block_num).await.unwrap().unwrap();
                        let proof =
                            provider.get_proof(addr, vec![], Some(block_num.into())).await.unwrap();
                        let mut proof = json_to_mpt_input(proof, ACCOUNT_PROOF_MAX_DEPTH, 0);
                        proof.acct_pf.root_hash = block.state_root;
                        CircuitInputAccountSubquery {
                            block_number: block_num,
                            field_idx: field_idx as u32,
                            proof,
                        }
                    },
                ))
                .await;
                let file = File::create(format!(
                    "{cargo_manifest_dir}/data/test/input_account_for_agg.json"
                ))?;
                serde_json::to_writer(file, &results)?;

                results
            }
            Ok(file) => serde_json::from_reader(file).unwrap(),
        };

    let promise_header = OutputBeaconShard {
        results: requests
            .iter()
            .map(|r| AnySubqueryResult {
                subquery: HeaderSubquery {
                    block_number: r.block_number as u32,
                    field_idx: STATE_ROOT_INDEX as u32,
                },
                value: r.proof.acct_pf.root_hash,
            })
            .collect(),
    };

    subquery_results.extend(promise_header.results.iter().map(|r| SubqueryResult {
        subquery: r.subquery.clone().into(),
        value: r.value.as_fixed_bytes().into(),
    }));

    let header_capacity = promise_header.len();

    let circuit_params = dummy_rlc_circuit_params(k as usize);
    let mut circuit = ComponentCircuitAccountSubquery::new(
        CoreParamsAccountSubquery {
            capacity: requests.len(),
            max_trie_depth: ACCOUNT_PROOF_MAX_DEPTH,
        },
        (
            PromiseLoaderParams::new_for_one_shard(KECCAK_F_CAPACITY),
            PromiseLoaderParams::new_for_one_shard(header_capacity),
        ),
        circuit_params,
    );

    let input =
        CircuitInputAccountShard::<Fr> { requests: requests.clone(), _phantom: PhantomData };
    circuit.feed_input(Box::new(input.clone())).unwrap();

    // subquery_results.push(SubqueryResult {
    //     subquery: beacon_input.request.clone().into(),
    //     value: H256::from_slice(beacon_input.exec_payload.state_root.as_ref()).0.into(),
    // })

    keccak_witnesses
        .extend(generate_keccak_shards_from_calls(&circuit, KECCAK_F_CAPACITY).unwrap().responses);

    promise_results.extend([
        (
            ComponentTypeKeccak::<Fr>::get_type_id(),
            ComponentPromiseResultsInMerkle::from_single_shard(
                OutputKeccakShard {
                    responses: keccak_witnesses.clone(),
                    capacity: KECCAK_F_CAPACITY,
                }
                .into_logical_results(),
            ),
        ),
        (
            ComponentTypeBeaconSubquery::<Fr>::get_type_id(), // Use `ComponentTypeBeaconSubquery` instead of `ComponentTypeHeaderSubquery`
            shard_into_component_promise_results::<Fr, ComponentTypeBeaconSubquery<Fr>>(
                promise_header.into(),
            ),
        ),
    ]);
    circuit.fulfill_promise_results(promise_results).unwrap();
    circuit.calculate_params();

    // MockProver::run(k, &circuit, circuit.instances()).unwrap().assert_satisfied();

    Ok(move |params: &ParamsKZG<Bn256>, promise_results: &GroupedPromiseResults<Fr>| {
        generate_snark("account_subquery_for_agg", params, circuit, &|pinning| {
            let circuit = ComponentCircuitAccountSubquery::<Fr>::prover(
                CoreParamsAccountSubquery {
                    capacity: requests.len(),
                    max_trie_depth: ACCOUNT_PROOF_MAX_DEPTH,
                },
                (
                    PromiseLoaderParams::new_for_one_shard(KECCAK_F_CAPACITY),
                    PromiseLoaderParams::new_for_one_shard(header_capacity),
                ),
                pinning,
            );
            circuit.feed_input(Box::new(input.clone())).unwrap();
            circuit.fulfill_promise_results(promise_results).unwrap();
            circuit
        })
    })
}

async fn generate_storage_snark(
    params: &ParamsKZG<Bn256>,
    network: Chain,
    subqueries: Vec<(u64, &str, H256)>, // (blockNum, addr, slot)
    subquery_results: &mut Vec<SubqueryResult>,
    promise_results: &mut GroupedPromiseResults<Fr>,
    keccak_witnesses: &mut Vec<(Bytes, Option<H256>)>,
) -> anyhow::Result<
    impl FnOnce(&ParamsKZG<Bn256>, &GroupedPromiseResults<Fr>) -> anyhow::Result<EnhancedSnark>,
> {
    let k = params.k();

    let _provider = setup_provider(network);
    let provider = &_provider;

    let (requests, storage_hashes, storage_results): (
        Vec<CircuitInputStorageSubquery>,
        Vec<H256>,
        Vec<AnySubqueryResult<StorageSubquery, H256>>,
    ) = itertools::multiunzip(
        join_all(subqueries.iter().copied().map(|(block_num, addr, slot)| async move {
            let addr = Address::from_str(addr).unwrap();
            let proof = provider.get_proof(addr, vec![slot], Some(block_num.into())).await.unwrap();
            let storage_hash = if proof.storage_hash.is_zero() {
                // RPC provider may give zero storage hash for empty account, but the correct storage hash should be the null root = keccak256(0x80)
                H256::from_slice(&axiom_eth::mpt::KECCAK_RLP_EMPTY_STRING)
            } else {
                proof.storage_hash
            };
            assert_eq!(proof.storage_proof.len(), 1, "Storage proof should have length 1 exactly");
            let value = u256_to_h256(&proof.storage_proof[0].value);
            let proof = json_to_mpt_input(proof, 0, STORAGE_PROOF_MAX_DEPTH);

            let storage_result = AnySubqueryResult {
                subquery: StorageSubquery {
                    block_number: block_num as u32,
                    addr,
                    slot: U256::from_big_endian(&slot.0),
                },
                value,
            };
            (
                CircuitInputStorageSubquery { block_number: block_num, proof },
                storage_hash,
                storage_result,
            )
        }))
        .await
        .into_iter(),
    );

    let promise_account = OutputAccountShard {
        results: requests
            .iter()
            .zip_eq(storage_hashes.clone())
            .map(|(r, storage_hash)| AnySubqueryResult {
                subquery: AccountSubquery {
                    block_number: r.block_number as u32,
                    field_idx: STORAGE_ROOT_INDEX as u32,
                    addr: r.proof.addr,
                },
                value: storage_hash,
            })
            .collect(),
    };

    subquery_results.extend(subqueries.iter().copied().zip(storage_hashes).map(
        |((block_num, addr, _), storage_hash)| {
            SubqueryResult {
                subquery: AccountSubquery {
                    block_number: block_num as u32,
                    field_idx: STORAGE_ROOT_INDEX as u32,
                    addr: Address::from_str(addr).unwrap(),
                }
                .into(),
                value: storage_hash.as_fixed_bytes().into(),
            }
        },
    ));

    // Adding storage results to the promise results to satisfy promise check in subquery aggregation.
    // In practice there will be other circuit querying storage that will provide these results, but this prototype skips that.
    {
        subquery_results.extend(subqueries.iter().copied().zip(&storage_results).map(
            |((block_num, addr, slot), result)| {
                SubqueryResult {
                    subquery: StorageSubquery {
                        block_number: block_num as u32,
                        addr: Address::from_str(addr).unwrap(),
                        slot: U256::from_big_endian(&slot.0),
                    }
                    .into(),
                    value: result.value.as_fixed_bytes().into(),
                }
            },
        ));

        promise_results.insert(
            ComponentTypeStorageSubquery::<Fr>::get_type_id(),
            shard_into_component_promise_results::<Fr, ComponentTypeStorageSubquery<Fr>>(
                OutputStorageShard { results: storage_results }.into(),
            ),
        );
    }

    let account_capacity = promise_account.results.len();

    let circuit_params = dummy_rlc_circuit_params(k as usize);
    let mut circuit = ComponentCircuitStorageSubquery::new(
        CoreParamsStorageSubquery {
            capacity: requests.len(),
            max_trie_depth: STORAGE_PROOF_MAX_DEPTH,
        },
        (
            PromiseLoaderParams::new_for_one_shard(KECCAK_F_CAPACITY),
            PromiseLoaderParams::new_for_one_shard(account_capacity),
        ),
        circuit_params,
    );

    let input =
        CircuitInputStorageShard::<Fr> { requests: requests.clone(), _phantom: PhantomData };
    circuit.feed_input(Box::new(input.clone())).unwrap();

    keccak_witnesses
        .extend(generate_keccak_shards_from_calls(&circuit, KECCAK_F_CAPACITY).unwrap().responses);

    promise_results.extend([
        (
            ComponentTypeKeccak::<Fr>::get_type_id(),
            ComponentPromiseResultsInMerkle::from_single_shard(
                OutputKeccakShard {
                    responses: keccak_witnesses.clone(),
                    capacity: KECCAK_F_CAPACITY,
                }
                .into_logical_results(),
            ),
        ),
        (
            ComponentTypeAccountSubquery::<Fr>::get_type_id(),
            shard_into_component_promise_results::<Fr, ComponentTypeAccountSubquery<Fr>>(
                promise_account.into(),
            ),
        ),
    ]);
    circuit.fulfill_promise_results(promise_results).unwrap();
    circuit.calculate_params();

    Ok(move |params: &ParamsKZG<Bn256>, promise_results: &GroupedPromiseResults<Fr>| {
        generate_snark("storage_subquery_for_agg", params, circuit, &|pinning| {
            let circuit = ComponentCircuitStorageSubquery::<Fr>::prover(
                CoreParamsStorageSubquery {
                    capacity: requests.len(),
                    max_trie_depth: STORAGE_PROOF_MAX_DEPTH,
                },
                (
                    PromiseLoaderParams::new_for_one_shard(KECCAK_F_CAPACITY),
                    PromiseLoaderParams::new_for_one_shard(account_capacity),
                ),
                pinning,
            );
            circuit.feed_input(Box::new(input.clone())).unwrap();
            circuit.fulfill_promise_results(promise_results).unwrap();
            circuit
        })
    })
}

fn generate_results_snark(
    params: &ParamsKZG<Bn256>,
    promise_results: &mut GroupedPromiseResults<Fr>,
    subquery_results: Vec<SubqueryResult>,
    keccak_witnesses: &mut Vec<(Bytes, Option<H256>)>,
) -> anyhow::Result<EnhancedSnark> {
    let results_input = CircuitInputResultsRootShard::<Fr> {
        subqueries: SubqueryResultsTable::<Fr>::new(
            subquery_results.clone().into_iter().map(|r| r.try_into().unwrap()).collect_vec(),
        ),
        num_subqueries: Fr::from(subquery_results.len() as u64),
    };

    let result_rlc_params = dummy_rlc_circuit_params(params.k() as usize);

    let mut enabled_types = [false; NUM_SUBQUERY_TYPES];
    enabled_types[SubqueryType::Header as usize] = true;
    enabled_types[SubqueryType::Account as usize] = true;
    enabled_types[SubqueryType::Storage as usize] = true;

    let promise_results_params = {
        let mut params_per_comp = HashMap::new();
        params_per_comp.insert(
            ComponentTypeBeaconSubquery::<Fr>::get_type_id(),
            SingleComponentLoaderParams::new_for_one_shard(1),
        );
        params_per_comp.insert(
            ComponentTypeAccountSubquery::<Fr>::get_type_id(),
            SingleComponentLoaderParams::new_for_one_shard(1),
        );
        params_per_comp.insert(
            ComponentTypeStorageSubquery::<Fr>::get_type_id(),
            SingleComponentLoaderParams::new_for_one_shard(1),
        );

        MultiPromiseLoaderParams { params_per_component: params_per_comp }
    };

    let mut results_circuit = ComponentCircuitResultsRoot::<Fr>::new(
        CoreParamsResultRoot { enabled_types, capacity: results_input.subqueries.len() },
        (PromiseLoaderParams::new_for_one_shard(KECCAK_F_CAPACITY), promise_results_params.clone()),
        result_rlc_params,
    );
    results_circuit.feed_input(Box::new(results_input.clone())).unwrap();

    keccak_witnesses.extend(
        generate_keccak_shards_from_calls(&results_circuit, KECCAK_F_CAPACITY).unwrap().responses,
    );
    let keccak_merkle = ComponentPromiseResultsInMerkle::<Fr>::from_single_shard(
        OutputKeccakShard { responses: keccak_witnesses.clone(), capacity: KECCAK_F_CAPACITY }
            .into_logical_results(),
    );
    promise_results.insert(ComponentTypeKeccak::<Fr>::get_type_id(), keccak_merkle);

    results_circuit.fulfill_promise_results(promise_results).unwrap();
    results_circuit.calculate_params();

    let instances = results_circuit.instances();
    // println!("results_snark_mock: {:?}", instances);
    MockProver::run(params.k(), &results_circuit, instances).unwrap().assert_satisfied();

    let results_snark =
        generate_snark("results_root_for_agg", params, results_circuit, &|pinning| {
            let results_circuit = ComponentCircuitResultsRoot::<Fr>::prover(
                CoreParamsResultRoot { enabled_types, capacity: results_input.subqueries.len() },
                (
                    PromiseLoaderParams::new_for_one_shard(KECCAK_F_CAPACITY),
                    promise_results_params.clone(),
                ),
                pinning,
            );
            results_circuit.feed_input(Box::new(results_input.clone())).unwrap();
            results_circuit.fulfill_promise_results(promise_results).unwrap();
            results_circuit
        })
        .unwrap();

    Ok(results_snark)
}

fn gen_keccak_snark(
    keccak_params: &ParamsKZG<Bn256>,
    merkle_agg_params: &ParamsKZG<Bn256>,
    keccak_shard: OutputKeccakShard,
) -> anyhow::Result<EnhancedSnark> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let k = keccak_params.k();
    let mut _keccak_params =
        KeccakComponentShardCircuitParams::new(k as usize, 109, keccak_shard.capacity, false);
    _keccak_params.base_circuit_params =
        KeccakComponentShardCircuit::<Fr>::calculate_base_circuit_params(&_keccak_params);

    let keygen_circuit =
        KeccakComponentShardCircuit::<Fr>::new(vec![], _keccak_params.clone(), false);

    let snark = {
        if let Ok(file) =
            File::open(format!("{cargo_manifest_dir}/configs/test/keccak_shard_for_agg.json"))
        {
            let break_points = serde_json::from_reader(file)?;
            keygen_circuit.set_base_circuit_break_points(break_points);
        }
        let pk = gen_pk(
            keccak_params,
            &keygen_circuit,
            Some(Path::new(&format!("{cargo_manifest_dir}/data/test/keccak_shard_for_agg.pk"))),
        );
        let break_points = keygen_circuit.base_circuit_break_points();
        let file =
            File::create(format!("{cargo_manifest_dir}/configs/test/keccak_shard_for_agg.json"))?;
        serde_json::to_writer(file, &break_points)?;
        let inputs = keccak_shard.responses.iter().map(|(k, _)| k.to_vec()).collect_vec();

        let prover_circuit = KeccakComponentShardCircuit::<Fr>::new(inputs, _keccak_params, true);
        prover_circuit.set_base_circuit_break_points(break_points);
        let snark_path = format!("{cargo_manifest_dir}/data/test/keccak_shard_for_agg.snark");
        gen_snark_shplonk(keccak_params, &pk, prover_circuit, Some(snark_path))
    };

    let k = merkle_agg_params.k();
    let agg_input = InputMerkleAggregation::new([EnhancedSnark::new(snark, None)]);

    let circuit_params =
        AggregationCircuitParams { degree: k, lookup_bits: k as usize - 1, ..Default::default() };
    let mut keygen_circuit =
        agg_input.clone().build(CircuitBuilderStage::Keygen, circuit_params, merkle_agg_params)?;
    keygen_circuit.calculate_params(Some(20));

    generate_snark("keccak_for_agg", merkle_agg_params, keygen_circuit, &|pinning| {
        agg_input.clone().prover_circuit(pinning, merkle_agg_params).unwrap()
    })
}

pub fn test_compute_circuit(
    k: u32,
    user_params: UserCircuitParams,
    subquery_results: LogicOutputResultsRoot,
    result_len: usize,
) -> BaseCircuitBuilder<Fr> {
    let circuit_params = user_params.base_circuit_params(k as usize);
    let mut builder = BaseCircuitBuilder::new(false).use_params(circuit_params);
    // let range = builder.range_chip();

    let ctx = builder.main(0);

    let mut compute_results = vec![];
    let mut data_instances = vec![];
    for result in subquery_results.results.into_iter().take(subquery_results.num_subqueries) {
        let result = FieldSubqueryResult::<Fr>::try_from(result).unwrap();
        let data_instance = ctx.assign_witnesses(result.to_fixed_array());
        compute_results.extend(data_instance[SUBQUERY_KEY_LEN..][..2].to_vec());
        data_instances.extend(data_instance);
    }
    assert!(compute_results.len() >= 2 * result_len);
    compute_results.truncate(2 * result_len);
    compute_results.resize_with(2 * USER_MAX_OUTPUTS, || ctx.load_witness(Fr::ZERO));

    let mut assigned_instance = compute_results;
    assigned_instance.extend(data_instances);
    assigned_instance
        .resize_with(DEFAULT_USER_PARAMS.num_instances(), || ctx.load_witness(Fr::ZERO));
    builder.assigned_instances[0] = assigned_instance;

    builder
}

fn generate_verify_compute(
    compute_name: &str,
    compute_params: &ParamsKZG<Bn256>,
    verify_params: &ParamsKZG<Bn256>,
    subquery_results: Vec<SubqueryResult>,
    keccak_witnesses: &mut Vec<(Bytes, Option<H256>)>,
    source_chain_id: u64,
) -> anyhow::Result<
    impl FnOnce(&ParamsKZG<Bn256>, &GroupedPromiseResults<Fr>) -> anyhow::Result<EnhancedSnark>,
> {
    let subquery_results = LogicOutputResultsRoot {
        subquery_hashes: subquery_results.iter().map(|r| r.subquery.keccak()).collect_vec(),
        num_subqueries: subquery_results.len(),
        results: subquery_results,
    };
    let result_len = subquery_results.num_subqueries;
    let max_num_subqueries = subquery_results.results.len();
    let app_k = compute_params.k();
    let mut logic_input = utils::get_base_input(
        compute_name,
        compute_params,
        USER_MAX_OUTPUTS,
        test_compute_circuit(app_k, DEFAULT_USER_PARAMS, subquery_results.clone(), result_len),
        subquery_results,
        source_chain_id,
        result_len,
    )?;

    // let default_input = utils::get_base_input(
    //     compute_name,
    //     compute_params,
    //     USER_MAX_OUTPUTS,
    //     default_compute_circuit(app_k),
    //     LogicOutputResultsRoot {
    //         results: vec![Default::default(); max_num_subqueries],
    //         subquery_hashes: vec![Default::default(); max_num_subqueries],
    //         num_subqueries: 0,
    //     },
    //     0,
    //     0,
    // )?;
    let (core_params, default_compute_circuit) =
        reconstruct_verify_compute_circuit(logic_input.clone(), compute_params)?;

    let circuit_k = verify_params.k();

    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let pinning_path = format!("{cargo_manifest_dir}/configs/test/verify_{compute_name}.json");
    let pk_path = format!("{cargo_manifest_dir}/data/test/verify_{compute_name}.pk");

    let circuit = {
        let k = circuit_k as usize;
        let mut rlc_params = dummy_rlc_circuit_params(k);
        rlc_params.base.lookup_bits = Some(k - 1);
        let loader_params = PromiseLoaderParams::new_for_one_shard(KECCAK_F_CAPACITY);
        let mut circuit =
            ComponentCircuitVerifyCompute::new(core_params, loader_params, rlc_params);
        circuit.feed_input(Box::new(default_compute_circuit)).unwrap();
        circuit.calculate_params();
        let promise_results = HashMap::from_iter([(
            ComponentTypeKeccak::<Fr>::get_type_id(),
            ComponentPromiseResultsInMerkle::from_single_shard(
                generate_keccak_shards_from_calls(&circuit, KECCAK_F_CAPACITY)
                    .unwrap()
                    .into_logical_results(),
            ),
        )]);
        circuit.fulfill_promise_results(&promise_results).unwrap();
        circuit
    };
    let (pk, pinning) = circuit.create_pk(verify_params, pk_path, pinning_path)?;

    let loader_params = PromiseLoaderParams::new_for_one_shard(KECCAK_F_CAPACITY);

    let first = logic_input.subquery_results.results[0].clone();
    logic_input.subquery_results.results.resize(max_num_subqueries, first);
    let first = logic_input.subquery_results.subquery_hashes[0];
    logic_input.subquery_results.subquery_hashes.resize(max_num_subqueries, first);
    let (core_params, input) = reconstruct_verify_compute_circuit(logic_input, compute_params)?;
    let circuit =
        ComponentCircuitVerifyCompute::prover(core_params, loader_params, pinning.clone());
    circuit.feed_input(Box::new(input)).unwrap();

    keccak_witnesses
        .extend(generate_keccak_shards_from_calls(&circuit, KECCAK_F_CAPACITY).unwrap().responses);

    // let promise_results = HashMap::from_iter([(
    //     ComponentTypeKeccak::<Fr>::get_type_id(),
    //     ComponentPromiseResultsInMerkle::<Fr>::from_single_shard(
    //         OutputKeccakShard { responses: keccak_witnesses.clone(), capacity: KECCAK_F_CAPACITY }
    //             .into_logical_results(),
    //     )
    // )]);
    let snark_path = format!("{cargo_manifest_dir}/data/test/verify_{compute_name}.snark");

    Ok(move |params: &ParamsKZG<Bn256>, promise_results: &GroupedPromiseResults<Fr>| {
        circuit.fulfill_promise_results(promise_results).unwrap();
        let snark = gen_snark_shplonk(params, &pk, circuit, Some(snark_path));

        Ok(EnhancedSnark::new(snark, None))
    })
}
