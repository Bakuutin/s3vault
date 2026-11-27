//! Promote on read: a GET that misses the store of record and is served from the fallback also writes that
//! object to the store, in the background, so the next read is served from the store.
//!
//! The read path never waits for the store: it fetches the whole object from the fallback into a spool
//! (verified: size, and MD5 against a plain ETag), answers the client from that spool, and hands the same
//! spool to the bounded promotion queue. A ranged read fetches the whole object too, so the promotion never
//! needs a second fallback transfer. Workers then write it with the fill's rules ([`Vault::store_filled`]):
//! under the per-key lock, create-only (an existing row, from a live write or the fill, wins), never over a
//! tombstone, encrypted like every write, recorded in the index (the fill then skips it).
//!
//! Limits: the queue is bounded by entries and by bytes held; a full queue drops the promotion (`deferred`)
//! and the background fill copies the key later. Promotions spend the bucket's fill byte budget
//! ([`Throttle`]) with priority over the fill, so they keep going while the fill is throttled.

use crate::spool::Spool;
use crate::vault::{ObjInfo, StoreFilled, Vault, VaultError, now_ms};
use serde::Serialize;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

// ------------------------------------------------------------------ throttle

/// A token bucket in bytes per second, shared by a bucket's background fill and its promotions. A priority
/// caller (a promotion) is served before any normal caller (the fill) while it waits; both draw from the
/// same budget, so together they stay within the rate.
pub struct Throttle {
    state: Mutex<ThrottleState>,
    prio_waiting: AtomicUsize,
}

struct ThrottleState {
    rate: u64,
    tokens: f64,
    last: Instant,
}

struct CountGuard<'a>(&'a AtomicUsize);

impl<'a> CountGuard<'a> {
    fn new(c: &'a AtomicUsize) -> Self {
        c.fetch_add(1, Ordering::SeqCst);
        CountGuard(c)
    }
}

impl Drop for CountGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Throttle {
    pub fn new(rate: u64) -> Self {
        let rate = rate.max(1);
        Throttle {
            state: Mutex::new(ThrottleState {
                rate,
                tokens: rate as f64,
                last: Instant::now(),
            }),
            prio_waiting: AtomicUsize::new(0),
        }
    }

    pub fn rate(&self) -> u64 {
        self.state.lock().unwrap().rate
    }

    /// Change the rate (a fill started with `rate=`); the current balance is kept, capped at one second.
    pub fn set_rate(&self, rate: u64) {
        let mut st = self.state.lock().unwrap();
        st.rate = rate.max(1);
        st.tokens = st.tokens.min(st.rate as f64);
    }

    /// Normal caller (the fill): waits for the budget and while any priority caller waits.
    pub async fn acquire(&self, n: u64) {
        self.take(n, false).await
    }

    /// Priority caller (a promotion): served before the fill, same budget.
    pub async fn acquire_priority(&self, n: u64) {
        let _g = CountGuard::new(&self.prio_waiting);
        self.take(n, true).await
    }

    async fn take(&self, n: u64, prio: bool) {
        loop {
            let wait = {
                let mut st = self.state.lock().unwrap();
                let now = Instant::now();
                let rate = st.rate as f64;
                st.tokens =
                    (st.tokens + now.duration_since(st.last).as_secs_f64() * rate).min(rate);
                st.last = now;
                // An object larger than one second of budget needs a full bucket, then goes into debt.
                let need = (n as f64).min(rate);
                let yield_to_prio = !prio && self.prio_waiting.load(Ordering::SeqCst) > 0;
                if !yield_to_prio && st.tokens >= need {
                    st.tokens -= n as f64;
                    return;
                }
                ((need - st.tokens) / rate).max(0.0)
            };
            // Short steps, so a rate change or a priority waiter is noticed quickly.
            tokio::time::sleep(Duration::from_secs_f64(wait.clamp(0.005, 0.25))).await;
        }
    }
}

// ------------------------------------------------------------------ promotion queue

pub struct PromoteJob {
    pub bucket: String,
    pub key: String,
    pub spool: Arc<Spool>,
    pub info: ObjInfo,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PromoteStatus {
    pub enabled: bool,
    pub queue_max: usize,
    pub queue_max_bytes: u64,
    pub concurrency: usize,
    pub queue_depth: usize,
    pub queue_bytes: u64,
    pub in_flight: usize,
    /// Accepted into the queue.
    pub enqueued: u64,
    /// Written to the store.
    pub promoted: u64,
    pub promoted_bytes: u64,
    /// The key already had a live row (a live write or the fill got there first).
    pub skipped_exists: u64,
    /// The key was deleted (tombstone) before the promotion ran.
    pub skipped_tombstone: u64,
    /// Not queued: the queue was full (the background fill copies these later).
    pub deferred: u64,
    /// Not queued: the same key was already waiting or in flight.
    pub duplicate: u64,
    pub failed: u64,
    pub last_error: Option<String>,
    pub last_error_ms: Option<i64>,
}

#[derive(Default)]
struct Queue {
    jobs: VecDeque<PromoteJob>,
    /// Waiting or in flight, by (bucket, key).
    pending: HashSet<(String, String)>,
    bytes: u64,
    workers: usize,
}

#[derive(Default)]
pub struct Promoter {
    q: Mutex<Queue>,
    enqueued: AtomicU64,
    promoted: AtomicU64,
    promoted_bytes: AtomicU64,
    skipped_exists: AtomicU64,
    skipped_tombstone: AtomicU64,
    deferred: AtomicU64,
    duplicate: AtomicU64,
    failed: AtomicU64,
    last_error: Mutex<Option<(String, i64)>>,
}

enum Outcome {
    Promoted(u64),
    Exists,
    Tombstoned,
}

impl Promoter {
    /// Queue a promotion. Returns false when it was not queued (full queue or already pending).
    pub fn enqueue(&self, vault: Arc<Vault>, job: PromoteJob) -> bool {
        let f = &vault.cfg.fill;
        let id = (job.bucket.clone(), job.key.clone());
        let spawn = {
            let mut q = self.q.lock().unwrap();
            if q.pending.contains(&id) {
                self.duplicate.fetch_add(1, Ordering::Relaxed);
                return false;
            }
            // The byte cap bounds what queued spools hold (RAM up to `memory_spool_max` each, else an
            // encrypted temp file); one object larger than the cap still goes through an empty queue.
            let over_bytes = !q.jobs.is_empty() && q.bytes + job.info.size > f.promote_queue_bytes;
            if q.jobs.len() >= f.promote_queue || over_bytes {
                self.deferred.fetch_add(1, Ordering::Relaxed);
                debug!(bucket = %job.bucket, "promotion queue full: deferred to the fill");
                return false;
            }
            q.bytes += job.info.size;
            q.pending.insert(id);
            q.jobs.push_back(job);
            self.enqueued.fetch_add(1, Ordering::Relaxed);
            let spawn = q.workers < f.promote_concurrency.max(1);
            if spawn {
                q.workers += 1;
            }
            spawn
        };
        if spawn {
            tokio::spawn(worker(vault));
        }
        true
    }

    pub fn status(&self, vault: &Vault) -> PromoteStatus {
        let f = &vault.cfg.fill;
        let q = self.q.lock().unwrap();
        let le = self.last_error.lock().unwrap().clone();
        PromoteStatus {
            enabled: f.promote_on_read,
            queue_max: f.promote_queue,
            queue_max_bytes: f.promote_queue_bytes,
            concurrency: f.promote_concurrency.max(1),
            queue_depth: q.jobs.len(),
            queue_bytes: q.bytes,
            in_flight: q.pending.len() - q.jobs.len(),
            enqueued: self.enqueued.load(Ordering::Relaxed),
            promoted: self.promoted.load(Ordering::Relaxed),
            promoted_bytes: self.promoted_bytes.load(Ordering::Relaxed),
            skipped_exists: self.skipped_exists.load(Ordering::Relaxed),
            skipped_tombstone: self.skipped_tombstone.load(Ordering::Relaxed),
            deferred: self.deferred.load(Ordering::Relaxed),
            duplicate: self.duplicate.load(Ordering::Relaxed),
            failed: self.failed.load(Ordering::Relaxed),
            last_error: le.as_ref().map(|e| e.0.clone()),
            last_error_ms: le.map(|e| e.1),
        }
    }

    /// True when nothing is waiting or in flight.
    pub fn idle(&self) -> bool {
        self.q.lock().unwrap().pending.is_empty()
    }

    fn next(&self) -> Option<PromoteJob> {
        let mut q = self.q.lock().unwrap();
        match q.jobs.pop_front() {
            Some(j) => {
                q.bytes -= j.info.size;
                Some(j)
            }
            None => {
                q.workers -= 1;
                None
            }
        }
    }

    fn done(&self, bucket: &str, key: &str) {
        self.q
            .lock()
            .unwrap()
            .pending
            .remove(&(bucket.to_string(), key.to_string()));
    }
}

async fn worker(vault: Arc<Vault>) {
    while let Some(job) = vault.promoter.next() {
        let p = &vault.promoter;
        match promote_one(&vault, &job).await {
            Ok(Outcome::Promoted(n)) => {
                p.promoted.fetch_add(1, Ordering::Relaxed);
                p.promoted_bytes.fetch_add(n, Ordering::Relaxed);
            }
            Ok(Outcome::Exists) => {
                p.skipped_exists.fetch_add(1, Ordering::Relaxed);
            }
            Ok(Outcome::Tombstoned) => {
                p.skipped_tombstone.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                p.failed.fetch_add(1, Ordering::Relaxed);
                warn!(bucket = %job.bucket, "promotion failed (the fill copies it later): {e}");
                *p.last_error.lock().unwrap() = Some((e.to_string(), now_ms()));
            }
        }
        p.done(&job.bucket, &job.key);
    }
}

async fn promote_one(vault: &Vault, job: &PromoteJob) -> Result<Outcome, VaultError> {
    let u = vault.unlocked()?;
    let (b, t) = vault.tenant_of(&u, &job.bucket)?;
    // Cheap check first, so a key that is already settled spends no budget (decided again under the lock).
    if let Some(r) = t.index.get(&b.name, &job.key)? {
        return Ok(if r.state == crate::index::TOMBSTONE {
            Outcome::Tombstoned
        } else {
            Outcome::Exists
        });
    }
    if let Some(th) = vault.fill_throttle(&b.name) {
        th.acquire_priority(job.info.size).await;
    }
    Ok(
        match vault
            .store_filled(&t, &b, &job.key, &job.spool, &job.info)
            .await?
        {
            StoreFilled::Stored => Outcome::Promoted(job.info.size),
            StoreFilled::Present => Outcome::Exists,
            StoreFilled::Tombstoned => Outcome::Tombstoned,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn throttle_limits_rate() {
        let th = Throttle::new(10_000);
        let t0 = Instant::now();
        // 10 kB start balance, then 30 kB more at 10 kB/s: about 3 s.
        for _ in 0..4 {
            th.acquire(10_000).await;
        }
        let e = t0.elapsed().as_secs_f64();
        assert!((2.7..4.0).contains(&e), "{e}");
    }

    #[tokio::test]
    async fn throttle_priority_goes_first() {
        let th = Arc::new(Throttle::new(10_000));
        th.acquire(10_000).await; // empty the bucket
        let order = Arc::new(Mutex::new(Vec::new()));
        let fill = {
            let (th, order) = (th.clone(), order.clone());
            tokio::spawn(async move {
                for _ in 0..3 {
                    th.acquire(5_000).await;
                    order.lock().unwrap().push("fill");
                }
            })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        let prio = {
            let (th, order) = (th.clone(), order.clone());
            tokio::spawn(async move {
                for _ in 0..3 {
                    th.acquire_priority(5_000).await;
                    order.lock().unwrap().push("prio");
                }
            })
        };
        let t0 = Instant::now();
        prio.await.unwrap();
        // The three promotions took (about) the first 15 kB of budget: no starvation by the fill.
        assert!(
            t0.elapsed() < Duration::from_millis(2_200),
            "{:?}",
            t0.elapsed()
        );
        fill.await.unwrap();
        // Both shared one budget: 30 kB after an empty start at 10 kB/s is about 3 s in total.
        assert!(
            t0.elapsed() > Duration::from_millis(2_500),
            "{:?}",
            t0.elapsed()
        );
        let o = order.lock().unwrap().clone();
        assert_eq!(o, ["prio", "prio", "prio", "fill", "fill", "fill"]);
    }

    #[tokio::test]
    async fn throttle_rate_change() {
        let th = Throttle::new(1_000);
        th.acquire(1_000).await;
        th.set_rate(1_000_000);
        let t0 = Instant::now();
        th.acquire(100_000).await;
        assert!(
            t0.elapsed() < Duration::from_millis(400),
            "{:?}",
            t0.elapsed()
        );
    }
}
