//! Core:
//! - CommitteeUpdate Poseidon root
//!
//! Shard:
//! - Step

use axiom_codec::{
    types::{field_elements::FieldHeaderSubquery, native::HeaderSubquery},
    HiLo,
};
use axiom_eth::{
    utils::{
        build_utils::{aggregation::CircuitMetadata, dummy::DummyFrom},
        bytes_be_to_u128,
        component::{
            circuit::{
                ComponentBuilder, CoreBuilder, CoreBuilderOutput, CoreBuilderOutputParams,
                CoreBuilderParams,
            },
            promise_collector::PromiseCaller,
            promise_loader::empty::EmptyPromiseLoader,
            types::{FixLenLogical, Flatten, LogicalEmpty},
            utils::get_logical_value,
            ComponentType, ComponentTypeId, LogicalResult,
        },
    },
    Field,
};
use axiom_query::components::subqueries::{
    block_header::{circuit::PromiseLoaderHeaderSubquery, types::ComponentTypeHeaderSubquery},
    storage::circuit::PayloadStorageSubquery,
};
use ethereum_consensus_types::{
    light_client::ExecutionPayloadHeader,
    presets::minimal::{BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES},
};
use halo2_base::{
    gates::flex_gate::threads::CommonCircuitBuilder, halo2_proofs::plonk::ConstraintSystem,
    safe_types::SafeTypeChip, AssignedValue,
};
use halo2_ecc::bls12_381::FpChip;
use itertools::Itertools;
use lightclient_circuits::{
    gadget::crypto::{Sha256Chip, ShaCircuitBuilder, ShaFlexGateManager},
    ssz_merkle::verify_merkle_proof,
    sync_step_circuit::StepCircuit,
    witness::SyncStepArgs,
};
use lightclient_circuits::{gadget::to_bytes_le, util::IntoWitness};
use serde::{Deserialize, Serialize};
use spectre_eth_types::{Mainnet, LIMB_BITS, NUM_LIMBS};
use std::marker::PhantomData;

use crate::comp_circuit_impl::ComponentCircuitImpl;

pub type ComponentCircuitBeaconSubquery<F> =
    ComponentCircuitImpl<F, CoreBuilderBeaconSubquery<F>, EmptyPromiseLoader<F>>;

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

pub const EXEC_BLOCK_NUM_GINDEX: usize = 22; // TODO;

// gindex stateRoot 18n
// gindex receiptsRoot 19n
// gindex blockNumber 22n
// gindex transactionsRoot 29n
pub const EXEC_PAYLOAD_FIELD_GINDECES: [usize; 4] = [18, 19, 22, 29]; // TODO;

pub const EXEC_STATE_ROOT_INDEX: usize = 0;

pub struct ComponentTypeBeaconSubquery<F: Field>(PhantomData<F>);

pub const BITS_PER_FE_BEACON: [usize; 2] = [32, 32];

impl<F: Field> ComponentType<F> for ComponentTypeBeaconSubquery<F> {
    type InputValue = FieldHeaderSubquery<F>;
    type InputWitness = FieldHeaderSubquery<AssignedValue<F>>;
    type OutputValue = HiLo<F>;
    type OutputWitness = HiLo<AssignedValue<F>>;
    type LogicalInput = FieldHeaderSubquery<F>;

    fn get_type_id() -> ComponentTypeId {
        // "spectre:BeaconSubquery".to_string()

        // use same subquery type id to be remain compatible with Results and SubqueryAggregation circuits
        // that have this id hard wired into constraints
        ComponentTypeHeaderSubquery::<F>::get_type_id()
    }

    fn logical_result_to_virtual_rows_impl(
        ins: &LogicalResult<F, Self>,
    ) -> Vec<(Self::InputValue, Self::OutputValue)> {
        vec![(ins.input, ins.output)]
    }
    fn logical_input_to_virtual_rows_impl(li: &Self::LogicalInput) -> Vec<Self::InputValue> {
        vec![*li]
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

pub struct CoreBuilderBeaconSubquery<F: Field> {
    input: Option<CircuitInputBeaconShard>,
    params: CoreParamsBeaconSubquery,
    payload: Option<Vec<PayloadStorageSubquery<F>>>,
}

impl<F: Field> ComponentBuilder<F> for CoreBuilderBeaconSubquery<F> {
    type Params = CoreParamsBeaconSubquery;

    fn new(params: Self::Params) -> Self {
        Self { input: None, params, payload: None }
    }
    fn get_params(&self) -> Self::Params {
        self.params.clone()
    }
    fn clear_witnesses(&mut self) {
        self.payload = None;
    }
    fn calculate_params(&mut self) -> Self::Params {
        self.params.clone()
    }
    fn configure_with_params(_: &mut ConstraintSystem<F>, _: Self::Params) {}
}

impl DummyFrom<CoreParamsBeaconSubquery> for CircuitInputBeaconShard {
    fn dummy_from(core_params: CoreParamsBeaconSubquery) -> Self {
        Default::default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogicalPublicInstanceBeacon<T: Copy> {
    pub pub_inputs_commit: T,
    pub poseidon_commit: T,
}

impl<F: Field> CircuitMetadata for CoreBuilderBeaconSubquery<F> {
    const HAS_ACCUMULATOR: bool = false;
    fn num_instance(&self) -> Vec<usize> {
        unreachable!()
    }
}

impl<F: Field> CoreBuilder<F> for CoreBuilderBeaconSubquery<F> {
    type CompType = ComponentTypeBeaconSubquery<F>;
    type PublicInstanceValue = LogicalPublicInstanceBeacon<F>;
    type PublicInstanceWitness = LogicalPublicInstanceBeacon<AssignedValue<F>>;
    type CoreInput = CircuitInputBeaconShard;
    type CircuitBuilder = ShaCircuitBuilder<F, ShaFlexGateManager<F>>;

    fn feed_input(&mut self, input: Self::CoreInput) -> anyhow::Result<()> {
        self.input = Some(input);
        Ok(())
    }

    fn virtual_assign_phase0(
        &mut self,
        // TODO: This could be replaced with a more generic CircuitBuilder. Question: can be CircuitBuilder treated as something like PromiseCircuit?
        builder: &mut Self::CircuitBuilder,
        // Core circuits can make promise calls.
        _promise_caller: PromiseCaller<F>, // Not yet supported
                                           // TODO: Output commitmment
    ) -> CoreBuilderOutput<F, Self::CompType> {
        let range = builder.range_chip();
        let fp_chip = FpChip::new(&range, LIMB_BITS, NUM_LIMBS);
        let input = self.input.as_ref().unwrap();
        let sha256_chip = Sha256Chip::new(&range);

        let (public_instances, execution_payload_root) =
            StepCircuit::virtual_assign(builder, &fp_chip, &input.step_args).unwrap();

        let field_idx = F::from(input.request.field_idx as u64);
        let assigned_field_idx = builder.main().load_witness(field_idx);

        let block_number = F::from(input.request.block_number as u64);
        let execution_block_number = builder.main().load_witness(block_number);
        let execution_block_number_bytes =
            to_bytes_le::<_, 32>(&execution_block_number, &range.gate, builder.main());

        // Verify execution chain block number against current state root via the Merkle proof
        verify_merkle_proof(
            builder,
            &sha256_chip,
            input.exec_block_num_branch.iter().map(|w| w.clone().into_witness()),
            execution_block_number_bytes.clone().into(),
            &execution_payload_root,
            EXEC_BLOCK_NUM_GINDEX,
        )
        .unwrap();

        let execution_payload_fields = [
            input.exec_payload.state_root,
            input.exec_payload.receipts_root,
            input.exec_payload.transactions_root,
        ];

        let execution_payload_field_bytes = execution_payload_fields
            [input.request.field_idx as usize] // TODO: make field index dynamic
            .as_ref()
            .iter()
            .map(|w| builder.main().load_witness(F::from(*w as u64)))
            .collect_vec();

        let execution_payload_field_hilo = HiLo::from_hi_lo(
            bytes_be_to_u128(
                builder.main(),
                &range.gate,
                SafeTypeChip::unsafe_to_fix_len_bytes_vec(
                    execution_payload_field_bytes.clone(),
                    32,
                )
                .bytes(),
            )
            .try_into()
            .unwrap(),
        );

        // Verify execution payload field against current state root via the Merkle proof
        verify_merkle_proof(
            builder,
            &sha256_chip,
            input.exec_payload_field_branch.iter().map(|w| w.clone().into_witness()),
            execution_payload_field_bytes.clone().into(),
            &execution_payload_root,
            EXEC_PAYLOAD_FIELD_GINDECES[input.request.field_idx as usize],
        )
        .unwrap();

        CoreBuilderOutput {
            public_instances,
            virtual_table: vec![(
                FieldHeaderSubquery {
                    block_number: execution_block_number,
                    field_idx: assigned_field_idx,
                }
                .into(),
                execution_payload_field_hilo.into(),
            )],
            logical_results: vec![LogicalResult::new(
                FieldHeaderSubquery { block_number, field_idx },
                get_logical_value(&execution_payload_field_hilo),
            )],
        }
    }
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
