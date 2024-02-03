use axiom_codec::types::native::HeaderSubquery;
use axiom_eth::block_header::STATE_ROOT_INDEX;
use beacon_api_client::{BlockId, Client, ClientTypes, StateId};
use ethereum_consensus_types::{
    light_client::ExecutionPayloadHeader,
    presets::minimal::{BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES},
    signing::{compute_domain, DomainType},
    ForkData,
};
use lightclient_circuits::witness::{get_helper_indices, merkle_tree};
use spectre_eth_types::Mainnet;
use spectre_preprocessor::{
    get_light_client_bootstrap, get_light_client_finality_update, step_args_from_finality_update,
};
use ssz_rs::{Merkleized, Node};

use crate::beacon_header::{
    map_field_idx_to_payload_gindex, types::CircuitInputBeaconShard, EXEC_BLOCK_NUM_GINDEX,
};

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
        field_idx: STATE_ROOT_INDEX as u32,
    };

    let exec_block_num_branch =
        beacon_header_proof(&mut finality_update.finalized_header.execution, EXEC_BLOCK_NUM_GINDEX)
            .into_iter()
            .map(|node| node.as_ref().to_vec())
            .collect::<Vec<_>>();

    let exec_payload_field_branch = beacon_header_proof(
        &mut finality_update.finalized_header.execution,
        map_field_idx_to_payload_gindex(request.field_idx),
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
