//! Core:
//! - CommitteeUpdate Poseidon root
//!
//! Shard:
//! - Step

use std::marker::PhantomData;

use axiom_codec::HiLo;
use axiom_eth::{
    impl_flatten_conversion, impl_logical_input,
    utils::{
        build_utils::dummy::DummyFrom,
        bytes_be_to_u128,
        component::{
            circuit::{
                ComponentBuilder, CoreBuilder, CoreBuilderOutput, CoreBuilderOutputParams,
                CoreBuilderParams,
            }, promise_collector::PromiseCaller, types::LogicalEmpty, utils::get_logical_value, ComponentType, ComponentTypeId, LogicalResult
        },
    },
    Field,
};
use axiom_query::components::subqueries::storage::circuit::PayloadStorageSubquery;
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
    witness::{HashInputChunk, SyncStepArgs},
};
use lightclient_circuits::{gadget::to_bytes_le, util::IntoWitness};
use serde::{Deserialize, Serialize};
use spectre_eth_types::{Mainnet, LIMB_BITS, NUM_LIMBS};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitInputBeaconShard {
    pub step_args: SyncStepArgs<Mainnet>,
    pub exec_block_num_branch: Vec<Vec<u8>>,
    pub exec_block_num: u64,
}

impl Default for CircuitInputBeaconShard {
    fn default() -> Self {
        todo!();
    }
}

const EXEC_BLOCK_NUM_INDEX: usize = 0; // TODO;

pub struct ComponentTypeBeaconSubquery<F: Field>(PhantomData<F>);

pub const BITS_PER_FE_BEACON: [usize; 1] = [32];

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct FieldBeaconSubquery<T> {
    pub block_number: T,
}

impl<T> TryFrom<Vec<T>> for FieldBeaconSubquery<T> {
    type Error = std::io::Error;

    fn try_from(value: Vec<T>) -> std::io::Result<Self> {
        let [block_number] = value.try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid array length")
        })?;
        Ok(Self { block_number })
    }
}

impl<T: Copy> FieldBeaconSubquery<T> {
    pub fn flatten(self) -> [T; 1] {
        [self.block_number]
    }
}

impl_logical_input!(FieldBeaconSubquery, 1);
impl_flatten_conversion!(FieldBeaconSubquery, BITS_PER_FE_BEACON);

impl<F: Field> ComponentType<F> for ComponentTypeBeaconSubquery<F> {
    type InputValue = FieldBeaconSubquery<F>;
    type InputWitness = FieldBeaconSubquery<AssignedValue<F>>;
    type OutputValue = HiLo<F>;
    type OutputWitness = HiLo<AssignedValue<F>>;
    type LogicalInput = FieldBeaconSubquery<F>;

    fn get_type_id() -> ComponentTypeId {
        "spectre:BeaconSubquery".to_string()
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

impl<F: Field> CoreBuilder<F> for CoreBuilderBeaconSubquery<F> {
    type CompType = ComponentTypeBeaconSubquery<F>;
    type PublicInstanceValue = LogicalEmpty<F>;
    type PublicInstanceWitness = LogicalEmpty<AssignedValue<F>>;
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
        let input = self.input.take().unwrap();
        let sha256_chip = Sha256Chip::new(&range);

        let (public_instances, execution_header_root) =
            StepCircuit::synthesize(builder, &fp_chip, &input.step_args).unwrap();

        let execution_header_root_bytes =
            SafeTypeChip::unsafe_to_fix_len_bytes_vec(execution_header_root.clone(), 32);

        let execution_header_root_hilo = HiLo::from_hi_lo(
            bytes_be_to_u128(builder.main(), &range.gate, execution_header_root_bytes.bytes())
                .try_into()
                .unwrap(),
        );

        let block_number = F::from(input.exec_block_num);
        let execution_block_number = builder.main().load_witness(block_number);
        let execution_block_number_bytes =
            to_bytes_le::<_, 32>(&execution_block_number, &range.gate, builder.main());

        // Verify execution chain block number against current state root via the Merkle proof
        verify_merkle_proof(
            builder,
            &sha256_chip,
            input.exec_block_num_branch.iter().map(|w| w.clone().into_witness()),
            execution_header_root.clone().into(),
            &execution_block_number_bytes.to_vec(),
            EXEC_BLOCK_NUM_INDEX,
        ).unwrap();

        CoreBuilderOutput {
            public_instances,
            virtual_table: Default::default(),
            logical_results: vec![LogicalResult::new(
                FieldBeaconSubquery { block_number },
                get_logical_value(&execution_header_root_hilo),
            )],
        }
    }
}

fn pad_to_32(le_bytes: &[u8]) -> Vec<u8> {
    assert!(le_bytes.len() <= 32);
    let mut chunk = le_bytes.to_vec();
    chunk.resize(32, 0);
    chunk
}
