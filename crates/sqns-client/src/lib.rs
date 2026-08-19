//! Client side of sqns: resolve public keys to endpoints, and publish your own.
//!
//! ```no_run
//! # async fn example() -> sqns_core::Result<()> {
//! use sqns_client::Resolver;
//!
//! let resolver = Resolver::single("sqc://ns1.example.com:5300/EFj2YJz…".parse()?)?;
//! for endpoint in resolver.resolve(&"7Cc…".parse()?).await? {
//!     println!("try {}", endpoint.authority());
//! }
//! # Ok(())
//! # }
//! ```

pub mod cache;
pub mod conn;
pub mod publisher;
pub mod resolver;
pub mod select;

pub use cache::Cache;
pub use publisher::{DEFAULT_TTL, Publisher};
pub use resolver::{Resolver, ResolverConfig, hex_seed};
pub use select::order_endpoints;
