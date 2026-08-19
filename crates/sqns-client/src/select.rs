//! Endpoint ordering.
//!
//! Endpoints are grouped by ascending priority; within a priority, entries are
//! drawn by weight without replacement, so a caller walking the list in order
//! spreads load across equal-priority endpoints while still failing over to the
//! next priority band. Zero-weight endpoints sort last within their band and
//! are only reached when every heavier sibling has failed.

use rand::Rng;
use sqns_core::record::{Endpoint, Record};

/// Endpoints in the order a caller should try them.
pub fn order_endpoints(record: &Record) -> Vec<Endpoint> {
    order_with(record, &mut rand::rng())
}

/// Same as [`order_endpoints`], with a caller-supplied RNG (used by tests).
pub fn order_with<R: Rng>(record: &Record, rng: &mut R) -> Vec<Endpoint> {
    let mut bands: Vec<(u16, Vec<Endpoint>)> = Vec::new();
    let mut sorted = record.endpoints().to_vec();
    sorted.sort_by_key(|e| e.priority);
    for ep in sorted {
        match bands.last_mut() {
            Some((prio, band)) if *prio == ep.priority => band.push(ep),
            _ => bands.push((ep.priority, vec![ep])),
        }
    }

    let mut out = Vec::with_capacity(record.endpoints().len());
    for (_, mut band) in bands {
        while !band.is_empty() {
            let total: u64 = band.iter().map(|e| e.weight as u64).sum();
            let idx = if total == 0 {
                0
            } else {
                let mut pick = rng.random_range(0..total);
                let mut chosen = band.len() - 1;
                for (i, ep) in band.iter().enumerate() {
                    let w = ep.weight as u64;
                    if pick < w {
                        chosen = i;
                        break;
                    }
                    pick -= w;
                }
                chosen
            };
            out.push(band.remove(idx));
        }
    }
    out
}
