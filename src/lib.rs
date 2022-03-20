//! Quick and dirty parser for NetFlow and sFlow data

extern crate nom;

#[macro_use]
extern crate lazy_static;

/// Module dealing with parsing NetFlow data
pub mod netflow_parse;

/// Module dealing with parsing sFlow data
pub mod sflow_parse;
