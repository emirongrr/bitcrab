//! Bitcoin specific storage tables

pub const HEADERS: &str = "headers";
pub const BODIES: &str = "bodies";
pub const BLOCK_INDEX: &str = "block_index";

pub const TABLES: [&str; 3] = [HEADERS, BODIES, BLOCK_INDEX];
