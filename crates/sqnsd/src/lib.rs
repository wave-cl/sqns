//! The sqns server, as a library so it can be driven from tests and embedded
//! in a supervisor.

pub mod config;
pub mod link;
pub mod replication;
pub mod server;
pub mod store;
pub mod upstream;

pub use config::{Config, FileConfig};
pub use server::{Bound, bind, run, serve};
pub use store::{PutOutcome, Store};
