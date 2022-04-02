//! Quick and dirty parser for NetFlow and sFlow data
//!
//! Regular parsing is performed using the [netflow_parse::NetflowParser] struct for NetFlow and the [sflow_parse::datagram::parse_sflow_data]
//! function for sFlow (no state required).

extern crate nom;

#[macro_use]
extern crate lazy_static;

#[cfg(feature = "netflow")]
pub mod netflow_parse;

#[cfg(feature = "sflow")]
pub mod sflow_parse;
