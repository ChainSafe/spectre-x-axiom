/// Circuit and Component Implementation.
pub mod circuit;
/// Types
pub mod types;

pub const EXEC_BLOCK_NUM_GINDEX: usize = 22; // TODO;

// gindex stateRoot 18n
// gindex receiptsRoot 19n
// gindex blockNumber 22n
// gindex transactionsRoot 29n
pub const EXEC_PAYLOAD_FIELD_GINDECES: [usize; 4] = [18, 19, 22, 29]; // TODO;

pub const EXEC_STATE_ROOT_INDEX: usize = 0;
