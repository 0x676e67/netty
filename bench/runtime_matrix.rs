use std::{
    future::Future,
    sync::Arc,
    time::{Duration, Instant},
};

pub struct Case {
    pub proto: bool,
    pub concurrency: usize,
    pub seconds: u64,
    pub server_runtime: tokio::runtime::Handle,
    pub barrier: Arc<tokio::sync::Barrier>,
}

pub struct Measurement {
    pub samples: Samples,
    pub started: Instant,
    pub finished: Instant,
}

pub fn run<F, Fut>(protocol: &str, measure: F)
where
    F: Fn(Case) -> Fut + Copy + Send + 'static,
    Fut: Future<Output = Measurement> + Send,
{
    let seconds: u64 = std::env::var("CLIENT_BENCH_SECONDS").map_or(2, |s| s.parse().unwrap());
    let rounds: usize = std::env::var("CLIENT_BENCH_ROUNDS").map_or(3, |s| s.parse().unwrap());
    assert!(seconds > 0 && rounds > 0);
    let server = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("bench-server")
        .enable_all()
        .build()
        .unwrap();
    println!("round,protocol,client_mode,client_threads,connections,total_concurrency,per_connection_concurrency,implementation,requests,seconds,requests_per_second,p50_us_upper,p99_us_upper");
    let mode_filter = std::env::var("CLIENT_BENCH_MODE").ok();
    let total_filter = std::env::var("CLIENT_BENCH_CONCURRENCY")
        .ok()
        .map(|s| s.parse::<usize>().unwrap());
    let implementation_filter = std::env::var("CLIENT_BENCH_IMPLEMENTATION").ok();
    let mut cases = 0;
    for round in 0..rounds {
        for (mode, threads, connections, totals) in [
            ("single", 1, 1, &[1, 4, 32, 128][..]),
            ("shared", 4, 1, &[1, 4, 32, 128][..]),
            ("sharded", 4, 4, &[4, 32, 128][..]),
        ] {
            if mode_filter.as_deref().is_some_and(|value| value != mode) {
                continue;
            }
            for &total in totals {
                if total_filter.is_some_and(|value| value != total) {
                    continue;
                }
                for proto in if round % 2 == 0 {
                    [false, true]
                } else {
                    [true, false]
                } {
                    let implementation = if proto { "wreq-proto" } else { protocol };
                    if implementation_filter
                        .as_deref()
                        .is_some_and(|value| value != implementation)
                    {
                        continue;
                    }
                    cases += 1;
                    let barrier = Arc::new(tokio::sync::Barrier::new(connections));
                    let mut workers = Vec::new();
                    for _ in 0..connections {
                        let case = Case {
                            proto,
                            concurrency: total / connections,
                            seconds,
                            server_runtime: server.handle().clone(),
                            barrier: barrier.clone(),
                        };
                        workers.push(
                            std::thread::Builder::new()
                                .name("bench-client".into())
                                .spawn(move || {
                                    let mut builder = if mode == "shared" {
                                        let mut builder =
                                            tokio::runtime::Builder::new_multi_thread();
                                        builder.worker_threads(threads);
                                        builder
                                    } else {
                                        tokio::runtime::Builder::new_current_thread()
                                    };
                                    let runtime = builder.enable_all().build().unwrap();
                                    runtime.block_on(async {
                                        tokio::time::timeout(
                                            Duration::from_secs(seconds + 30),
                                            measure(case),
                                        )
                                        .await
                                        .expect("benchmark worker timed out")
                                    })
                                })
                                .unwrap(),
                        );
                    }
                    let measurements: Vec<_> =
                        workers.into_iter().map(|w| w.join().unwrap()).collect();
                    let started = measurements.iter().map(|m| m.started).min().unwrap();
                    let finished = measurements.iter().map(|m| m.finished).max().unwrap();
                    let elapsed = (finished - started).as_secs_f64();
                    let mut samples = Samples::new();
                    for m in measurements {
                        samples.merge(m.samples);
                    }
                    let implementation = if proto { "wreq-proto" } else { protocol };
                    println!("{round},{protocol},{mode},{threads},{connections},{total},{},{implementation},{},{elapsed:.6},{:.2},{},{}", total / connections, samples.total, samples.total as f64 / elapsed, samples.percentile(50), samples.percentile(99));
                }
            }
        }
    }
    assert!(cases > 0, "no matching benchmark cases");
}

// A bounded histogram with at least five significant binary bits per bucket.
// Recording is local to each worker; there is no measurement lock in the loop.
pub struct Samples {
    counts: [u64; 1920],
    pub total: u64,
}

impl Samples {
    pub fn new() -> Self {
        Self {
            counts: [0; 1920],
            total: 0,
        }
    }

    pub fn record(&mut self, elapsed: Duration) {
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        let index = if micros < 64 {
            micros as usize
        } else {
            let shift = 63 - micros.leading_zeros() - 5;
            64 + (shift as usize - 1) * 32 + ((micros >> shift) as usize - 32)
        };
        self.counts[index] += 1;
        self.total += 1;
    }

    pub fn merge(&mut self, other: Self) {
        for (count, added) in self.counts.iter_mut().zip(other.counts) {
            *count += added;
        }
        self.total += other.total;
    }

    fn percentile(&self, percent: u64) -> u64 {
        let rank = (u128::from(self.total) * u128::from(percent)).div_ceil(100) as u64;
        let mut count = 0;
        for (index, &samples) in self.counts.iter().enumerate() {
            count += samples;
            if count >= rank {
                if index < 64 {
                    return index as u64;
                }
                let shift = (index - 64) / 32 + 1;
                let mantissa = (index - 64) % 32 + 32;
                let upper = (((mantissa + 1) as u128) << shift) - 1;
                return u64::try_from(upper).unwrap_or(u64::MAX);
            }
        }
        u64::MAX
    }
}
