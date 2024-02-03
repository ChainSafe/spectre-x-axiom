use axiom_codec::types::native::HeaderSubquery;
use axiom_eth::{utils::{build_utils::dummy::DummyFrom, component::{circuit::{CoreBuilderOutputParams, CoreBuilderParams}, types::{FixLenLogical, Flatten}}}, Field};
use axiom_query::components::subqueries::{block_header::types::ComponentTypeHeaderSubquery, common::OutputSubqueryShard};
use ethereum_consensus_types::{light_client::ExecutionPayloadHeader, presets::minimal::{BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES}};
use ethers_core::types::H256;
use lightclient_circuits::witness::SyncStepArgs;
use serde::{Deserialize, Serialize};
use spectre_eth_types::Mainnet;

pub type ComponentTypeBeaconSubquery<F> = ComponentTypeHeaderSubquery<F>;

pub type OutputBeaconShard = OutputSubqueryShard<HeaderSubquery, H256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitInputBeaconShard {
    pub request: HeaderSubquery,

    pub step_args: SyncStepArgs<Mainnet>,
    pub exec_block_num_branch: Vec<Vec<u8>>,

    pub exec_payload_field_branch: Vec<Vec<u8>>,
    pub exec_payload: ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
}

impl Default for CircuitInputBeaconShard {
    fn default() -> Self {
        todo!();
    }
}

impl DummyFrom<CoreParamsBeaconSubquery> for CircuitInputBeaconShard {
    fn dummy_from(_core_params: CoreParamsBeaconSubquery) -> Self {
        Default::default()
    }
}


/// Specify the output format of BeaconSubquery component.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CoreParamsBeaconSubquery {
    /// The maximum number of subqueries of this type allowed in a single circuit.
    pub capacity: usize,
}

impl CoreBuilderParams for CoreParamsBeaconSubquery {
    fn get_output_params(&self) -> CoreBuilderOutputParams {
        CoreBuilderOutputParams::new(vec![self.capacity])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalPublicInstanceBeacon<T: Copy> {
    pub pub_inputs_commit: T,
    pub poseidon_commit: T,
}


impl<T: Copy> TryFrom<Vec<T>> for LogicalPublicInstanceBeacon<T> {
    type Error = anyhow::Error;

    fn try_from(value: Vec<T>) -> Result<Self, Self::Error> {
        if value.len() != BITS_PER_PUBLIC_INSTANCE.len() {
            return Err(anyhow::anyhow!("incorrect length"));
        }
        Ok(Self { pub_inputs_commit: value[0], poseidon_commit: value[1] })
    }
}

const BITS_PER_PUBLIC_INSTANCE: [usize; 2] = [32, 32];

impl<T: Copy> TryFrom<Flatten<T>> for LogicalPublicInstanceBeacon<T> {
    type Error = anyhow::Error;

    fn try_from(value: Flatten<T>) -> Result<Self, Self::Error> {
        if value.field_size != BITS_PER_PUBLIC_INSTANCE {
            return Err(anyhow::anyhow!("invalid field size"));
        }
        value.fields.try_into()
    }
}
impl<T: Copy> From<LogicalPublicInstanceBeacon<T>> for Flatten<T> {
    fn from(val: LogicalPublicInstanceBeacon<T>) -> Self {
        Flatten {
            fields: vec![val.pub_inputs_commit, val.poseidon_commit],
            field_size: &BITS_PER_PUBLIC_INSTANCE,
        }
    }
}
impl<T: Copy> FixLenLogical<T> for LogicalPublicInstanceBeacon<T> {
    fn get_field_size() -> &'static [usize] {
        &BITS_PER_PUBLIC_INSTANCE
    }
}
