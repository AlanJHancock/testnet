//! Regression tests for the chain/tx_pool lock-ordering invariant.
//!
//! Background (commit 7ac21bde): the consensus block-production loop used to
//! acquire `TX_POOL` and then the chain lock, while RPC handlers acquire the
//! chain lock and then `TX_POOL`. Both run as threads in one node process and
//! share the same global mutexes, which is the classic AB-BA deadlock shape.
//!
//! Canonical order (must hold everywhere both are held at once):
//!     chain  ->  TX_POOL
//!
//! Two kinds of protection live here:
//!   1. `source_*` tests read the production source and fail if any function
//!      takes `TX_POOL` before a chain lock. This is what catches the original
//!      bug, which was two `let` lines in the wrong order.
//!   2. `concurrent_*` tests drive the real global statics from many threads in
//!      the canonical order under a watchdog, so a deadlock fails the test
//!      instead of hanging CI forever.

use std::fs;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use synergy_testnet::rpc::rpc_server::{SHARED_CHAIN, TX_POOL};

const CONSENSUS_SRC: &str = "consensus/consensus_algorithm.rs";
const RPC_SRC: &str = "rpc/rpc_server.rs";

/// Run `f` on a thread and fail if it does not finish within `limit`.
/// A deadlocked thread cannot be killed, so it is simply abandoned; the test
/// process exits when the harness finishes.
fn finishes_within<F: FnOnce() + Send + 'static>(limit: Duration, f: F) -> bool {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    rx.recv_timeout(limit).is_ok()
}

/// 1-based line numbers of every `TX_POOL.lock()` that is followed, within the
/// same block, by a chain lock acquisition. In canonical order a chain lock
/// must already be held, so the chain lock must come FIRST.
fn lines_taking_pool_before_chain(src: &str) -> Vec<usize> {
    let lines: Vec<&str> = src.lines().collect();
    let mut bad = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let code = line.split("//").next().unwrap_or("");
        if !code.contains("TX_POOL.lock()") {
            continue;
        }
        // Look at the next few lines for a chain lock taken while the pool
        // guard is still live (a `let pool = TX_POOL.lock()...` binding).
        let binds_guard = code.trim_start().starts_with("let ");
        if !binds_guard {
            continue;
        }
        for follow in lines.iter().skip(i + 1).take(3) {
            let f = follow.split("//").next().unwrap_or("");
            let takes_chain = f.contains("chain.lock()")
                || f.contains("blockchain.lock()")
                || f.contains("SHARED_CHAIN.lock()");
            if takes_chain && f.trim_start().starts_with("let ") {
                bad.push(i + 1);
                break;
            }
        }
    }
    bad
}

#[test]
fn source_consensus_loop_takes_chain_before_tx_pool() {
    let src = fs::read_to_string(CONSENSUS_SRC).expect("read consensus source");
    let bad = lines_taking_pool_before_chain(&src);
    assert!(
        bad.is_empty(),
        "{CONSENSUS_SRC}: TX_POOL is locked before the chain lock at line(s) {bad:?}. \
         Canonical order is chain -> TX_POOL (see commit 7ac21bde); the reverse order \
         deadlocks against RPC handlers."
    );
}

#[test]
fn source_rpc_handlers_take_chain_before_tx_pool() {
    let src = fs::read_to_string(RPC_SRC).expect("read rpc source");
    let bad = lines_taking_pool_before_chain(&src);
    assert!(
        bad.is_empty(),
        "{RPC_SRC}: TX_POOL is locked before the chain lock at line(s) {bad:?}. \
         Canonical order is chain -> TX_POOL (see commit 7ac21bde)."
    );
}

#[test]
fn source_detector_flags_the_original_bug() {
    // Guards the guard: the exact shape of the pre-fix code must be caught,
    // and the fixed shape must not be.
    let buggy = "let pool = TX_POOL.lock().unwrap();\n\
                 let chain_guard = chain.lock().unwrap();\n";
    let fixed = "let chain_guard = chain.lock().unwrap();\n\
                 let pool = TX_POOL.lock().unwrap();\n";
    assert_eq!(lines_taking_pool_before_chain(buggy), vec![1]);
    assert!(lines_taking_pool_before_chain(fixed).is_empty());
}

#[test]
fn concurrent_canonical_order_never_deadlocks() {
    // Many threads hammer the REAL global statics in the canonical order,
    // standing in for consensus loop + RPC handlers + P2P. If the order were
    // inconsistent this would hang; the watchdog turns that into a failure.
    let ok = finishes_within(Duration::from_secs(20), || {
        let mut handles = Vec::new();
        for t in 0..8 {
            handles.push(thread::spawn(move || {
                for i in 0..2_000 {
                    let chain = SHARED_CHAIN.lock().unwrap_or_else(|e| e.into_inner());
                    let pool = TX_POOL.lock().unwrap_or_else(|e| e.into_inner());
                    // Touch both so the guards are genuinely held together.
                    let _ = (chain.chain.len(), pool.len(), t, i);
                    drop(pool);
                    drop(chain);
                }
            }));
        }
        for h in handles {
            h.join().expect("worker panicked");
        }
    });
    assert!(ok, "canonical chain -> TX_POOL order deadlocked or stalled");
}

#[test]
fn concurrent_inverted_order_is_detected_by_the_watchdog() {
    // Demonstrates the failure mode the fix removed, on PRIVATE mutexes (the
    // global statics are not touched, so this cannot wedge other tests).
    // Two threads take A,B and B,A with a barrier forcing the interleaving
    // that produces the deadlock. The watchdog must report it.
    use std::sync::{Arc, Barrier, Mutex};
    let a = Arc::new(Mutex::new(0u8));
    let b = Arc::new(Mutex::new(0u8));
    let gate = Arc::new(Barrier::new(2));

    let (a1, b1, g1) = (a.clone(), b.clone(), gate.clone());
    let (a2, b2, g2) = (a.clone(), b.clone(), gate.clone());

    let finished = finishes_within(Duration::from_secs(2), move || {
        let t1 = thread::spawn(move || {
            let _first = a1.lock().unwrap();
            g1.wait();
            let _second = b1.lock().unwrap();
        });
        let t2 = thread::spawn(move || {
            let _first = b2.lock().unwrap();
            g2.wait();
            let _second = a2.lock().unwrap();
        });
        let _ = (t1.join(), t2.join());
    });
    assert!(
        !finished,
        "inverted A->B / B->A order should deadlock; the watchdog is not detecting it"
    );
}
