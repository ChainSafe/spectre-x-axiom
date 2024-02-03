use axiom_eth::block_header::{
    BLOCK_NUMBER_INDEX, RECEIPT_ROOT_INDEX, STATE_ROOT_INDEX, TX_ROOT_INDEX,
};

/// Circuit and Component Implementation.
pub mod circuit;
/// Types
pub mod types;

pub const EXEC_BLOCK_NUM_GINDEX: usize = 22;

const EXEC_PAYLOAD_GINDECES_MAPPING: [(usize, usize); 4] = [
    (STATE_ROOT_INDEX, 18),
    (RECEIPT_ROOT_INDEX, 19),
    (BLOCK_NUMBER_INDEX, 22),
    (TX_ROOT_INDEX, 29),
];

pub fn map_field_idx_to_payload_gindex(idx: u32) -> usize {
    EXEC_PAYLOAD_GINDECES_MAPPING
        .binary_search_by(|(k, _)| k.cmp(&(idx as usize)))
        .map(|x| EXEC_PAYLOAD_GINDECES_MAPPING[x].1)
        .unwrap()
}
