//! An MCP server must not keep memory for every request it has answered
//! (#46). rmcp 1.8.0 kept each finished response-send task in a `JoinSet`
//! until the session ended, and a ContextVM session never ends; the copy in
//! `server/vendor/rmcp` reaps them as they finish, as rmcp 3.x does.
//!
//! The test counts live heap bytes with a global allocator, so it is the only
//! test in this binary: nothing else allocates while it measures.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use rmcp::ServiceExt;

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        System.alloc(layout)
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        System.dealloc(ptr, layout)
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        LIVE.fetch_add(new_size as isize - layout.size() as isize, Ordering::Relaxed);
        System.realloc(ptr, layout, new_size)
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

/// A server that answers with rmcp's defaults.
struct Quiet;

impl rmcp::ServerHandler for Quiet {}

const WARMUP: usize = 500;
const MEASURED: usize = 5_000;
/// Without the fix this server keeps 184 bytes per request (the real service,
/// with its larger send futures, kept about 7 KiB); with it, none.
const MAX_BYTES_PER_REQUEST: isize = 64;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answered_requests_do_not_keep_memory() {
    let (a, b) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let running = Quiet.serve(a).await.unwrap();
        let _ = running.waiting().await;
    });
    let client = ().serve(b).await.unwrap();

    for _ in 0..WARMUP {
        client.list_tools(None).await.unwrap();
    }
    let before = LIVE.load(Ordering::Relaxed);
    for _ in 0..MEASURED {
        client.list_tools(None).await.unwrap();
    }
    // Let the server's last response sends finish and be reaped.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let grown = LIVE.load(Ordering::Relaxed) - before;

    assert!(
        grown < MAX_BYTES_PER_REQUEST * MEASURED as isize,
        "live heap grew {grown} bytes over {MEASURED} requests ({} per request)",
        grown / MEASURED as isize
    );
}
