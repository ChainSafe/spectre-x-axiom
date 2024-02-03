#![feature(trait_alias)]
#![feature(associated_type_defaults)]
#![feature(associated_type_bounds)]
#![feature(generic_const_exprs)]
#![warn(clippy::useless_conversion)]

mod comp_circuit_impl;
mod spectre_component;

use std::{collections::HashMap, fs::File, marker::PhantomData, str::FromStr};

use axiom_codec::{
    constants::NUM_SUBQUERY_TYPES,
    types::{
        field_elements::AnySubqueryResult,
        native::{AccountSubquery, HeaderSubquery, SubqueryResult, SubqueryType},
    },
};
use axiom_eth::{
    halo2_proofs::halo2curves::bn256::Fr,
    keccak::{
        promise::generate_keccak_shards_from_calls,
        types::{ComponentTypeKeccak, OutputKeccakShard},
    },
    mpt::KECCAK_RLP_EMPTY_STRING,
    providers::{setup_provider, storage::json_to_mpt_input},
    snark_verifier_sdk::{halo2::gen_snark_shplonk, CircuitExt},
    utils::{
        build_utils::pinning::{BaseCircuitPinning, PinnableCircuit, RlcCircuitPinning},
        component::{
            circuit::ComponentBuilder,
            param,
            promise_loader::{
                comp_loader::SingleComponentLoaderParams, multi::MultiPromiseLoaderParams,
                single::PromiseLoaderParams,
            },
            ComponentCircuit, ComponentPromiseResultsInMerkle, ComponentType,
            GroupedPromiseResults,
        },
        snark_verifier::{AggregationCircuitParams, EnhancedSnark},
    },
};
use axiom_query::{
    components::{
        dummy_rlc_circuit_params,
        results::{
            circuit::{ComponentCircuitResultsRoot, CoreParamsResultRoot},
            table::SubqueryResultsTable,
            types::CircuitInputResultsRootShard,
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
            block_header::{
                circuit::PromiseLoaderHeaderSubquery,
                types::{ComponentTypeHeaderSubquery, OutputHeaderShard},
            },
            common::{shard_into_component_promise_results, OutputSubqueryShard},
            storage::{
                circuit::{ComponentCircuitStorageSubquery, CoreParamsStorageSubquery},
                types::{CircuitInputStorageShard, CircuitInputStorageSubquery},
            },
        },
    },
    subquery_aggregation::types::InputSubqueryAggregation,
};
use beacon_api_client::{BlockId, Client, ClientTypes, StateId};
use ethereum_consensus_types::{
    light_client::ExecutionPayloadHeader,
    presets::minimal::{BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES},
    signing::{compute_domain, DomainType},
    ForkData, LightClientBootstrap,
};
use ethers_core::types::{transaction::request, Address, Chain, H256};
use ethers_providers::Middleware;
use futures::future::join_all;
use halo2_base::{
    gates::circuit::{BaseCircuitParams, CircuitBuilderStage},
    halo2_proofs::{
        dev::MockProver,
        poly::{commitment::Params, kzg::commitment::ParamsKZG},
    },
    utils::fs::gen_srs,
};
use halo2curves::bn256::Bn256;
use itertools::Itertools;
use lightclient_circuits::{
    sync_step_circuit::StepCircuit,
    util::{AppCircuit, Eth2ConfigPinning},
    witness::{get_helper_indices, merkle_tree},
};
use spectre_component::{
    CircuitInputBeaconShard, ComponentCircuitBeaconSubquery, ComponentTypeBeaconSubquery,
    CoreParamsBeaconSubquery, EXEC_BLOCK_NUM_GINDEX, EXEC_PAYLOAD_FIELD_GINDECES,
    EXEC_STATE_ROOT_INDEX,
};
use spectre_eth_types::{Mainnet, Spec};
use spectre_preprocessor::{
    get_light_client_bootstrap, get_light_client_finality_update, step_args_from_finality_update,
};
use ssz_rs::{Merkleized, Node};
use std::io::Write;
use url::Url;

pub const ACCOUNT_PROOF_MAX_DEPTH: usize = 13;
pub const STORAGE_PROOF_MAX_DEPTH: usize = 13;

#[tokio::main]
async fn main() {
    const AGG_K: u32 = 19;
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");
    let header_params = gen_srs(20);

    let mut subquery_results = vec![];
    let (header_snark, mut promise_results) =
        generate_header_snark(&header_params, &mut subquery_results).await.unwrap();
    // let keccak_commit =
    //     promise_results.get(&ComponentTypeKeccak::<Fr>::get_type_id()).unwrap().leaves()[0].commit;

    let results_input = CircuitInputResultsRootShard::<Fr> {
        subqueries: SubqueryResultsTable::<Fr>::new(
            subquery_results.clone().into_iter().map(|r| r.try_into().unwrap()).collect_vec(),
        ),
        num_subqueries: Fr::from(subquery_results.len() as u64),
    };

    let results_circuit_k = AGG_K;
    let result_rlc_params = dummy_rlc_circuit_params(results_circuit_k as usize);

    let mut enabled_types = [false; NUM_SUBQUERY_TYPES];
    enabled_types[SubqueryType::Header as usize] = true;

    let promise_results_params = {
        let mut params_per_comp = HashMap::new();
        params_per_comp.insert(
            ComponentTypeHeaderSubquery::<Fr>::get_type_id(), // we keep using ComponentTypeHeaderSubquery so we don't need to modify Results circuit
            SingleComponentLoaderParams::new(0, vec![1]),     // what is shard_caps?
        );

        MultiPromiseLoaderParams { params_per_component: params_per_comp }
    };

    let mut results_circuit = ComponentCircuitResultsRoot::<Fr>::new(
        CoreParamsResultRoot { enabled_types, capacity: results_input.subqueries.len() },
        (PromiseLoaderParams::new_for_one_shard(200), promise_results_params.clone()),
        result_rlc_params,
    );
    results_circuit.feed_input(Box::new(results_input.clone())).unwrap();

    let keccak_merkle = ComponentPromiseResultsInMerkle::<Fr>::from_single_shard(
        generate_keccak_shards_from_calls(&results_circuit, 200).unwrap().into_logical_results(),
    );
    promise_results.insert(ComponentTypeKeccak::<Fr>::get_type_id(), keccak_merkle);

    let keccak_commit =
        promise_results.get(&ComponentTypeKeccak::<Fr>::get_type_id()).unwrap().leaves()[0].commit;


    results_circuit.fulfill_promise_results(&promise_results).unwrap();
    results_circuit.calculate_params();

    // let instances = results_circuit.instances();
    // println!("results_snark_mock: {:?}", instances);
    // MockProver::run(results_circuit_k as u32, &results_circuit, instances).unwrap().assert_satisfied();

    let rslt_params = gen_srs(results_circuit_k);

    let results_snark =
        generate_snark("results_root_for_agg", &rslt_params, results_circuit, &|pinning| {
            let results_circuit = ComponentCircuitResultsRoot::<Fr>::prover(
                CoreParamsResultRoot { enabled_types, capacity: results_input.subqueries.len() },
                (PromiseLoaderParams::new_for_one_shard(200), promise_results_params.clone()),
                pinning,
            );
            results_circuit.feed_input(Box::new(results_input.clone())).unwrap();
            results_circuit.fulfill_promise_results(&promise_results).unwrap();
            results_circuit
        })
        .unwrap();

    let aggregation_payload = InputSubqueryAggregation {
        snark_header: header_snark,
        snark_results_root: results_snark,
        snark_account: None,
        snark_storage: None,
        snark_solidity_mapping: None,
        snark_tx: None,
        snark_receipt: None,
        promise_commit_keccak: keccak_commit,
    };

    let agg_params = rslt_params;

    let mut agg_circuit = aggregation_payload
        .build(
            CircuitBuilderStage::Mock,
            AggregationCircuitParams {
                degree: AGG_K,
                num_advice: 0,
                num_lookup_advice: 0,
                num_fixed: 0,
                lookup_bits: 8,
            },
            //rlc_circuit_params.base.try_into().unwrap(),
            &agg_params,
        )
        .unwrap();
    agg_circuit.calculate_params(Some(9));
    let instances = agg_circuit.instances();
    MockProver::run(AGG_K, &agg_circuit, instances).unwrap().assert_satisfied();
}

async fn generate_header_snark(
    params: &ParamsKZG<Bn256>,
    subquery_results: &mut Vec<SubqueryResult>,
) -> anyhow::Result<(EnhancedSnark, GroupedPromiseResults<Fr>)> {
    let cargo_manifest_dir = env!("CARGO_MANIFEST_DIR");

    // let beacon_input: CircuitInputBeaconShard = serde_json::from_reader(File::open(format!(
    //     "{cargo_manifest_dir}/data/test/input_beacon_for_agg.json"
    // ))?)?;

    let client = beacon_api_client::mainnet::Client::new(
        Url::parse("https://lodestar-holesky.chainsafe.io").unwrap(),
    );

    // let beacon_input = fetch_beacon_args(&client).await.unwrap();
    // // write beacon_input to file /data/test/promise_results_keccak_for_agg.json
    // let beacon_input_file =
    //     File::create(format!("{cargo_manifest_dir}/data/test/input_beacon_for_agg.json"))?;
    // serde_json::to_writer(beacon_input_file, &beacon_input)?;

    let beacon_input: CircuitInputBeaconShard = serde_json::from_reader(File::open(format!(
        "{cargo_manifest_dir}/data/test/input_beacon_for_agg.json"
    ))?)?;
    subquery_results.push(SubqueryResult {
        subquery: beacon_input.request.clone().into(),
        value: H256::from_slice(beacon_input.exec_payload.state_root.as_ref()).0.into(),
    });

    let mut promise_results = HashMap::new();

    // let promise_keccak: OutputKeccakShard = serde_json::from_reader(
    //     File::open(format!("{cargo_manifest_dir}/data/test/promise_results_keccak_for_agg.json"))
    //         .unwrap(),
    // )?;

    // let promise_header: OutputSubqueryShard<HeaderSubquery, H256> = serde_json::from_reader(
    //     File::open(format!("{cargo_manifest_dir}/data/test/promise_results_header_for_agg.json"))
    //         .unwrap(),
    // )?;

    // let promise_keccak = OutputKeccakShard { responses: vec![], capacity: 1 };
    // let keccak_merkle = ComponentPromiseResultsInMerkle::<Fr>::from_single_shard(
    //     promise_keccak.into_logical_results(),
    // );
    // promise_results.insert(ComponentTypeKeccak::<Fr>::get_type_id(), keccak_merkle);

    let promise_header = OutputSubqueryShard::<HeaderSubquery, H256> {
        results: vec![AnySubqueryResult {
            subquery: HeaderSubquery {
                block_number: beacon_input.request.block_number as u32,
                field_idx: EXEC_STATE_ROOT_INDEX as u32,
            },
            value: {
                let bytes: [_; 32] =
                    beacon_input.exec_payload.state_root.as_ref().try_into().unwrap();
                bytes.into()
            },
        }],
    };

    // WHY have header promise for header subquery?
    // Guess: for resutls circuit
    promise_results.insert(
        ComponentTypeHeaderSubquery::<Fr>::get_type_id(),
        shard_into_component_promise_results::<Fr, ComponentTypeHeaderSubquery<Fr>>(
            promise_header.convert_into(),
        ),
    );

    // let (header_core_params, header_promise_params, header_base_params) = read_beacon_pinning()?;
    let circuit_params = BaseCircuitParams {
        k: params.k() as usize,
        lookup_bits: Some(params.k() as usize - 1),
        num_instance_columns: 1,
        ..Default::default()
    };

    let mut beacon_circuit = ComponentCircuitBeaconSubquery::<Fr>::new(
        CoreParamsBeaconSubquery { capacity: 1 },
        (),
        circuit_params,
    );
    beacon_circuit.feed_input(Box::new(beacon_input.clone())).unwrap();
    beacon_circuit.calculate_params();
    beacon_circuit.fulfill_promise_results(&promise_results).unwrap();

    let header_snark =
        generate_snark("beacon_subquery_for_agg", params, beacon_circuit, &|pinning| {
            let circuit = ComponentCircuitBeaconSubquery::<Fr>::prover(
                CoreParamsBeaconSubquery { capacity: 1 },
                (),
                pinning,
            );
            circuit.feed_input(Box::new(beacon_input.clone())).unwrap();
            circuit.fulfill_promise_results(&promise_results).unwrap();
            circuit
        })?;
    Ok((header_snark, promise_results))
}

// #[test]
// fn test_mock_subquery_agg() -> anyhow::Result<()> {
//     let k = 19;
//     let params = gen_srs(k as u32);

//     let input = get_test_input(&params)?;
//     let mut agg_circuit = input.build(
//         CircuitBuilderStage::Mock,
//         AggregationCircuitParams {
//             degree: k as u32,
//             num_advice: 0,
//             num_lookup_advice: 0,
//             num_fixed: 0,
//             lookup_bits: 8,
//         },
//         //rlc_circuit_params.base.try_into().unwrap(),
//         &params,
//     )?;
//     agg_circuit.calculate_params(Some(9));
//     let instances = agg_circuit.instances();
//     MockProver::run(k as u32, &agg_circuit, instances).unwrap().assert_satisfied();
//     Ok(())
// }

fn generate_snark<C: CircuitExt<Fr> + PinnableCircuit<Pinning = RlcCircuitPinning>>(
    name: &'static str,
    params: &ParamsKZG<Bn256>,
    keygen_circuit: C,
    load_prover_circuit: &impl Fn(RlcCircuitPinning) -> C,
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

// Fetches the latest `LightClientFinalityUpdate`` and the current sync committee (from LightClientBootstrap) and converts it to a [`SyncStepArgs`] witness.
pub async fn fetch_beacon_args<C: ClientTypes>(
    client: &Client<C>,
) -> anyhow::Result<CircuitInputBeaconShard> {
    let mut finality_update = get_light_client_finality_update(client).await.unwrap();
    let block_root = client
        .get_beacon_block_root(BlockId::Slot(finality_update.finalized_header.beacon.slot))
        .await
        .unwrap();
    let bootstrap = get_light_client_bootstrap::<Mainnet, _>(client, block_root).await.unwrap();

    let pubkeys_compressed = bootstrap.current_sync_committee.pubkeys;

    let attested_state_id = finality_update.attested_header.beacon.state_root;

    let fork_version = client.get_fork(StateId::Root(attested_state_id)).await?.current_version;
    let genesis_validators_root = client.get_genesis_details().await?.genesis_validators_root;
    let fork_data = ForkData { genesis_validators_root, fork_version };
    let domain = compute_domain(DomainType::SyncCommittee, &fork_data)?;

    let step_args =
        step_args_from_finality_update(finality_update.clone(), pubkeys_compressed, domain)
            .await
            .unwrap();

    let request = HeaderSubquery {
        block_number: finality_update.finalized_header.execution.block_number as u32,
        field_idx: EXEC_STATE_ROOT_INDEX as u32,
    };

    let exec_block_num_branch =
        beacon_header_proof(&mut finality_update.finalized_header.execution, EXEC_BLOCK_NUM_GINDEX)
            .into_iter()
            .map(|node| node.as_ref().to_vec())
            .collect::<Vec<_>>();

    let exec_payload_field_branch = beacon_header_proof(
        &mut finality_update.finalized_header.execution,
        EXEC_PAYLOAD_FIELD_GINDECES[EXEC_STATE_ROOT_INDEX],
    )
    .into_iter()
    .map(|node| node.as_ref().to_vec())
    .collect::<Vec<_>>();

    Ok(CircuitInputBeaconShard {
        request,
        step_args,
        exec_block_num_branch,
        exec_payload_field_branch,
        exec_payload: finality_update.finalized_header.execution,
    })
}

pub fn beacon_header_proof(
    header: &mut ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    gindex: usize,
) -> Vec<Node> {
    let header_leaves = [
        header.parent_hash.hash_tree_root().unwrap(),
        header.fee_recipient.hash_tree_root().unwrap(),
        header.state_root.hash_tree_root().unwrap(),
        header.receipts_root.hash_tree_root().unwrap(),
        header.logs_bloom.hash_tree_root().unwrap(),
        header.prev_randao.hash_tree_root().unwrap(),
        header.block_number.hash_tree_root().unwrap(),
        header.gas_limit.hash_tree_root().unwrap(),
        header.gas_used.hash_tree_root().unwrap(),
        header.timestamp.hash_tree_root().unwrap(),
        header.extra_data.hash_tree_root().unwrap(),
        header.base_fee_per_gas.hash_tree_root().unwrap(),
        header.block_hash.hash_tree_root().unwrap(),
        header.transactions_root.hash_tree_root().unwrap(),
        header.withdrawals_root.hash_tree_root().unwrap(),
    ];
    let merkle_tree = merkle_tree(&header_leaves);
    let helper_indices = get_helper_indices(&[gindex]);
    let proof = helper_indices.iter().copied().map(|i| merkle_tree[i]).collect::<Vec<_>>();
    assert_eq!(proof.len(), helper_indices.len());
    proof
}

async fn generate_account_snark(
    k: u32,
    network: Chain,
    subqueries: Vec<(u64, &str, usize)>, // (blockNum, addr, fieldIdx)
    keccak_f_capacity: usize,
) -> anyhow::Result<EnhancedSnark> {
    let params = gen_srs(k);
    let _ = env_logger::builder().is_test(true).try_init();

    let _provider = setup_provider(network);
    let provider = &_provider;
    let requests =
        join_all(subqueries.into_iter().map(|(block_num, addr, field_idx)| async move {
            let addr = Address::from_str(addr).unwrap();
            let block = provider.get_block(block_num).await.unwrap().unwrap();
            let proof = provider.get_proof(addr, vec![], Some(block_num.into())).await.unwrap();
            let mut proof = json_to_mpt_input(proof, ACCOUNT_PROOF_MAX_DEPTH, 0);
            proof.acct_pf.root_hash = block.state_root;
            CircuitInputAccountSubquery {
                block_number: block_num,
                field_idx: field_idx as u32,
                proof,
            }
        }))
        .await;

    let mut promise_header = OutputHeaderShard {
        results: requests
            .iter()
            .map(|r| AnySubqueryResult {
                subquery: HeaderSubquery {
                    block_number: r.block_number as u32,
                    field_idx: EXEC_STATE_ROOT_INDEX as u32, // Note: this is diffrent from `axiom_eth::block_header::STATE_ROOT_INDEX`
                },
                value: r.proof.acct_pf.root_hash,
            })
            .collect(),
    };

    let header_capacity = promise_header.len();

    let circuit_params = dummy_rlc_circuit_params(k as usize);
    let mut circuit = ComponentCircuitAccountSubquery::new(
        CoreParamsAccountSubquery {
            capacity: requests.len(),
            max_trie_depth: ACCOUNT_PROOF_MAX_DEPTH,
        },
        (
            PromiseLoaderParams::new_for_one_shard(keccak_f_capacity),
            PromiseLoaderParams::new_for_one_shard(header_capacity),
        ),
        circuit_params,
    );

    let input =
        CircuitInputAccountShard::<Fr> { requests: requests.clone(), _phantom: PhantomData };
    circuit.feed_input(Box::new(input.clone())).unwrap();
    circuit.calculate_params();

    let promises = [
        (
            ComponentTypeKeccak::<Fr>::get_type_id(),
            ComponentPromiseResultsInMerkle::from_single_shard(
                generate_keccak_shards_from_calls(&circuit, keccak_f_capacity)
                    .unwrap()
                    .into_logical_results(),
            ),
        ),
        (
            ComponentTypeBeaconSubquery::<Fr>::get_type_id(), // Use `ComponentTypeBeaconSubquery` instead of `ComponentTypeHeaderSubquery`
            shard_into_component_promise_results::<Fr, ComponentTypeBeaconSubquery<Fr>>(
                promise_header.into(),
            ),
        ),
    ]
    .into_iter()
    .collect();
    circuit.fulfill_promise_results(&promises).unwrap();

    let account_snark = generate_snark("account_subquery_for_agg", &params, circuit, &|pinning| {
        let circuit = ComponentCircuitAccountSubquery::<Fr>::prover(
            CoreParamsAccountSubquery {
                capacity: requests.len(),
                max_trie_depth: ACCOUNT_PROOF_MAX_DEPTH,
            },
            (
                PromiseLoaderParams::new_for_one_shard(keccak_f_capacity),
                PromiseLoaderParams::new_for_one_shard(header_capacity),
            ),
            pinning,
        );
        circuit.feed_input(Box::new(input.clone())).unwrap();
        circuit.fulfill_promise_results(&promises).unwrap();
        circuit
    })?;

    Ok(account_snark)
}

async fn generate_storage_snark(
    k: u32,
    network: Chain,
    subqueries: Vec<(u64, &str, H256)>, // (blockNum, addr, slot)
) -> ComponentCircuitStorageSubquery<Fr> {
    let _ = env_logger::builder().is_test(true).try_init();

    let _provider = setup_provider(network);
    let provider = &_provider;
    let (requests, storage_hashes): (Vec<CircuitInputStorageSubquery>, Vec<H256>) =
        join_all(subqueries.into_iter().map(|(block_num, addr, slot)| async move {
            let addr = Address::from_str(addr).unwrap();
            let proof = provider.get_proof(addr, vec![slot], Some(block_num.into())).await.unwrap();
            let storage_hash = if proof.storage_hash.is_zero() {
                // RPC provider may give zero storage hash for empty account, but the correct storage hash should be the null root = keccak256(0x80)
                H256::from_slice(&KECCAK_RLP_EMPTY_STRING)
            } else {
                proof.storage_hash
            };
            assert_eq!(proof.storage_proof.len(), 1, "Storage proof should have length 1 exactly");
            let proof = json_to_mpt_input(proof, 0, STORAGE_PROOF_MAX_DEPTH);
            (CircuitInputStorageSubquery { block_number: block_num, proof }, storage_hash)
        }))
        .await
        .into_iter()
        .unzip();

    let promise_account = OutputAccountShard {
        results: requests
            .iter()
            .zip_eq(storage_hashes)
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

    let keccak_f_capacity = 1200;
    let account_capacity = promise_account.results.len();

    let circuit_params = dummy_rlc_circuit_params(k as usize);
    let mut circuit = ComponentCircuitStorageSubquery::new(
        CoreParamsStorageSubquery {
            capacity: requests.len(),
            max_trie_depth: STORAGE_PROOF_MAX_DEPTH,
        },
        (
            PromiseLoaderParams::new_for_one_shard(keccak_f_capacity),
            PromiseLoaderParams::new_for_one_shard(account_capacity),
        ),
        circuit_params,
    );

    let input = CircuitInputStorageShard::<Fr> { requests, _phantom: PhantomData };
    circuit.feed_input(Box::new(input)).unwrap();
    circuit.calculate_params();
    let promises = [
        (
            ComponentTypeKeccak::<Fr>::get_type_id(),
            ComponentPromiseResultsInMerkle::from_single_shard(
                generate_keccak_shards_from_calls(&circuit, keccak_f_capacity)
                    .unwrap()
                    .into_logical_results(),
            ),
        ),
        (
            ComponentTypeAccountSubquery::<Fr>::get_type_id(),
            shard_into_component_promise_results::<Fr, ComponentTypeAccountSubquery<Fr>>(
                promise_account.into(),
            ),
        ),
    ]
    .into_iter()
    .collect();
    circuit.fulfill_promise_results(&promises).unwrap();

    circuit
}
