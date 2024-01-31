#![feature(trait_alias)]
#![feature(associated_type_defaults)]
#![feature(associated_type_bounds)]
#![warn(clippy::useless_conversion)]

mod spectre_component;
mod comp_circuit_impl;

use std::{marker::PhantomData, str::FromStr};

use axiom_codec::types::{field_elements::AnySubqueryResult, native::AccountSubquery};
use axiom_eth::{
    halo2_proofs::halo2curves::bn256::Fr,
    keccak::{promise::generate_keccak_shards_from_calls, types::ComponentTypeKeccak},
    mpt::KECCAK_RLP_EMPTY_STRING,
    providers::{setup_provider, storage::json_to_mpt_input},
    snark_verifier_sdk::halo2::gen_snark_shplonk,
    utils::{
        build_utils::pinning::PinnableCircuit,
        component::{
            param, promise_loader::single::PromiseLoaderParams, ComponentCircuit,
            ComponentPromiseResultsInMerkle, ComponentType,
        },
    },
};
use axiom_query::components::{
    dummy_rlc_circuit_params,
    subqueries::{
        account::{
            types::{ComponentTypeAccountSubquery, OutputAccountShard},
            STORAGE_ROOT_INDEX,
        },
        common::shard_into_component_promise_results,
        storage::{
            circuit::{ComponentCircuitStorageSubquery, CoreParamsStorageSubquery},
            types::{CircuitInputStorageShard, CircuitInputStorageSubquery},
        },
    },
};
use ethers_core::types::{Address, Chain, H256};
use ethers_providers::Middleware;
use futures::future::join_all;
use halo2_base::utils::fs::gen_srs;
use itertools::Itertools;
use lightclient_circuits::{sync_step_circuit::StepCircuit, util::AppCircuit};

#[tokio::main]
async fn main() {
    let storage_snark = {
        let k = 18;
        let params = gen_srs(k);
        let subqueries = vec![
            (17143006, "0xEf1c6E67703c7BD7107eed8303Fbe6EC2554BF6B", H256::zero()),
            (17143000, "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45", H256::zero()),
            (16356350, "0xb47e3cd837dDF8e4c57F05d70Ab865de6e193BBB", H256::zero()),
            (15411056, "0x1c479675ad559DC151F6Ec7ed3FbF8ceE79582B6", H256::zero()),
        ];
        let circuit = get_storage_subqueries_circuit(k, Chain::Mainnet, subqueries).await;
        let (pk, pinning) = circuit
            .create_pk(&params, "./data/storage_4_18.pkey", "./config/storage_4_18.json")
            .unwrap();
        gen_snark_shplonk(&params, &pk, circuit, Some("./data/storage_4_18.proof"))
    };

    // let spectre_snark = {
    //     let k = 20;
    //     let params = gen_srs(k);
    //     let pk = StepCircuit::<Mainnet>::create_pk(
    //         &params,
    //         "./data/step_20.pkey",
    //         "./data/step_20.json",
    //         &Default::default(),
    //         None,
    //     )
    // };
}

pub const STORAGE_PROOF_MAX_DEPTH: usize = 13;

async fn get_storage_subqueries_circuit(
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
