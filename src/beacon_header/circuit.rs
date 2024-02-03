//! Core:
//! - CommitteeUpdate Poseidon root
//!
//! Shard:
//! - Step

use std::{collections::HashMap, marker::PhantomData};

use axiom_codec::{types::field_elements::FieldHeaderSubquery, HiLo};
use axiom_eth::{
    block_header::{RECEIPT_ROOT_INDEX, STATE_ROOT_INDEX, TX_ROOT_INDEX},
    utils::{
        build_utils::aggregation::CircuitMetadata,
        bytes_be_to_u128,
        component::{
            circuit::{ComponentBuilder, CoreBuilder, CoreBuilderOutput},
            promise_collector::PromiseCaller,
            promise_loader::empty::EmptyPromiseLoader,
            utils::get_logical_value,
            LogicalResult,
        },
    },
    Field,
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
};
use lightclient_circuits::{gadget::to_bytes_le, util::IntoWitness};
use spectre_eth_types::{LIMB_BITS, NUM_LIMBS};

use crate::{
    beacon_header::types::{
        CircuitInputBeaconShard, ComponentTypeBeaconSubquery, CoreParamsBeaconSubquery,
        LogicalPublicInstanceBeacon,
    },
    utils::ComponentCircuitImpl,
};

use super::{map_field_idx_to_payload_gindex, EXEC_BLOCK_NUM_GINDEX};

pub type ComponentCircuitBeaconSubquery<F> =
    ComponentCircuitImpl<F, CoreBuilderBeaconSubquery<F>, EmptyPromiseLoader<F>>;

pub struct CoreBuilderBeaconSubquery<F: Field> {
    input: Option<CircuitInputBeaconShard>,
    params: CoreParamsBeaconSubquery,
    _f: PhantomData<F>,
}

impl<F: Field> ComponentBuilder<F> for CoreBuilderBeaconSubquery<F> {
    type Params = CoreParamsBeaconSubquery;

    fn new(params: Self::Params) -> Self {
        Self { input: None, params, _f: PhantomData }
    }
    fn get_params(&self) -> Self::Params {
        self.params.clone()
    }
    fn clear_witnesses(&mut self) {}
    fn calculate_params(&mut self) -> Self::Params {
        self.params.clone()
    }
    fn configure_with_params(_: &mut ConstraintSystem<F>, _: Self::Params) {}
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

        let execution_payload_fields: HashMap<_, _> = [
            (STATE_ROOT_INDEX as u32, input.exec_payload.state_root),
            (RECEIPT_ROOT_INDEX as u32, input.exec_payload.receipts_root),
            (TX_ROOT_INDEX as u32, input.exec_payload.transactions_root),
        ]
        .into();

        let execution_payload_field_bytes = execution_payload_fields[&input.request.field_idx] // TODO: make field index dynamic
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
            map_field_idx_to_payload_gindex(input.request.field_idx),
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
