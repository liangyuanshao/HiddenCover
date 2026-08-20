use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use csv::Writer;
use hiddencover::{HiddenCover, RevocationState};
use rand::{seq::index::sample, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use std::{collections::HashSet, env, fs, path::PathBuf, time::Instant};

const WARMUPS: usize = 5;
const MEASUREMENTS: usize = 30;
const WORKLOAD_SEEDS: usize = 20;
const DISTRIBUTIONS: [&str; 3] = ["clustered", "random", "dispersed"];

#[derive(Serialize)]
struct Rq1Row<'a> {
    scheme: &'a str,
    capacity: usize,
    revoked: usize,
    distribution: &'a str,
    workload_seed: usize,
    measurement: usize,
    cover_nodes: usize,
    holder_upload_bytes: usize,
    holder_download_bytes: usize,
    holder_compute_ms: f64,
    server_per_holder_ms: f64,
    verified: bool,
}

#[derive(Serialize)]
struct Rq2Row<'a> {
    scheme: &'a str,
    capacity: usize,
    rate: f64,
    revoked: usize,
    distribution: &'a str,
    workload_seed: usize,
    cover_nodes: usize,
    public_state_bytes: usize,
    authority_refresh_ms: f64,
    verified: bool,
}

#[derive(Serialize)]
struct Rq3Row<'a> {
    scheme: &'a str,
    cover_nodes: usize,
    padded_set_size: usize,
    measurement: usize,
    presentation_bytes: usize,
    show_ms: f64,
    verify_ms: f64,
    state_check_ms: f64,
    match_ms: f64,
    credential_bridge_ms: f64,
    cover_transform_ms: f64,
    oom_ms: f64,
    verified: bool,
}

#[derive(Serialize)]
struct CredentialRow {
    depth: usize,
    capacity: usize,
    measurement: usize,
    setup_ms: f64,
    issue_ms: f64,
    credential_bytes: usize,
    path_signatures: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let output = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("benchmarks/results"));
    let mode = args.next().unwrap_or_else(|| "all".to_owned());
    fs::create_dir_all(&output)?;
    if mode == "all" || mode == "rq1" {
        benchmark_rq1(output.join("rq1_hiddencover.csv"))?;
    }
    if mode == "all" || mode == "rq2" {
        benchmark_rq2(output.join("rq2_hiddencover.csv"))?;
    }
    if mode == "all" || mode == "rq3" {
        benchmark_rq3_rq4(output.join("rq3_rq4_hiddencover.csv"))?;
    }
    if mode == "all" || mode == "credential" {
        benchmark_credentials(output.join("credential_hiddencover.csv"))?;
    }
    println!("benchmark mode {mode} written to {}", output.display());
    Ok(())
}

fn benchmark_rq1(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let capacity = 1usize << 14;
    let mut writer = Writer::from_path(path)?;
    let mut rng = ChaCha20Rng::seed_from_u64(0x7101_0000);
    let mut system = HiddenCover::setup(14, &mut rng)?;
    for revoked in [10usize, 30, 100, 300, 1_000, 3_000, 10_000] {
        for distribution in DISTRIBUTIONS {
            for workload_seed in 0..WORKLOAD_SEEDS {
                let leaves = workload(capacity, revoked, distribution, workload_seed as u64);
                let state = system.benchmark_replace_revoked(leaves)?;
                let wire = state.to_bytes();
                for _ in 0..WARMUPS {
                    let decoded = RevocationState::from_bytes(&wire)?;
                    system.benchmark_check_state(&decoded)?;
                }
                for measurement in 0..MEASUREMENTS {
                    let start = Instant::now();
                    let decoded = RevocationState::from_bytes(&wire)?;
                    let verified = system.benchmark_check_state(&decoded).is_ok();
                    let holder_compute_ms = start.elapsed().as_secs_f64() * 1_000.0;
                    writer.serialize(Rq1Row {
                        scheme: "HiddenCover",
                        capacity,
                        revoked,
                        distribution,
                        workload_seed,
                        measurement,
                        cover_nodes: state.cover.len(),
                        holder_upload_bytes: 0,
                        holder_download_bytes: wire.len(),
                        holder_compute_ms,
                        server_per_holder_ms: 0.0,
                        verified,
                    })?;
                }
            }
        }
    }
    writer.flush()?;
    Ok(())
}

fn benchmark_rq2(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let depth = 20;
    let capacity = 1usize << depth;
    let mut writer = Writer::from_path(path)?;
    for rate in [0.001f64, 0.01, 0.05, 0.10, 0.15] {
        let revoked = ((capacity as f64 * rate).round() as usize).max(1);
        for distribution in DISTRIBUTIONS {
            for workload_seed in 0..WORKLOAD_SEEDS {
                let mut rng = ChaCha20Rng::seed_from_u64(
                    0x7202_0000 + workload_seed as u64 + (rate * 1_000_000.0) as u64,
                );
                let mut system = HiddenCover::setup(depth, &mut rng)?;
                let leaves = workload(capacity, revoked, distribution, workload_seed as u64);
                let start = Instant::now();
                let state = system.benchmark_replace_revoked(leaves)?;
                let wire = state.to_bytes();
                let authority_refresh_ms = start.elapsed().as_secs_f64() * 1_000.0;
                let decoded = RevocationState::from_bytes(&wire)?;
                let verified = system.benchmark_check_state(&decoded).is_ok();
                writer.serialize(Rq2Row {
                    scheme: "HiddenCover",
                    capacity,
                    rate,
                    revoked,
                    distribution,
                    workload_seed,
                    cover_nodes: state.cover.len(),
                    public_state_bytes: wire.len(),
                    authority_refresh_ms,
                    verified,
                })?;
            }
        }
    }
    writer.flush()?;
    Ok(())
}

fn benchmark_rq3_rq4(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = Writer::from_path(path)?;
    let mut rng = ChaCha20Rng::seed_from_u64(0x7303_0000);
    let mut system = HiddenCover::setup(20, &mut rng)?;
    let credential = system.issue(&mut rng)?;
    let live_node = credential.path[0].node_value;
    for cover_nodes in [8usize, 16, 32, 64, 128, 256, 512, 1_024, 2_048, 4_096] {
        let mut cover = Vec::with_capacity(cover_nodes);
        cover.push(live_node);
        let mut seen = HashSet::from([live_node]);
        while cover.len() < cover_nodes {
            let value = Fr::rand(&mut rng);
            if seen.insert(value) {
                cover.push(value);
            }
        }
        let state = system.benchmark_replace_cover(cover);
        for warmup in 0..WARMUPS {
            let nonce = format!("warmup/{cover_nodes}/{warmup}");
            let (proof, _) = system.benchmark_show_with_breakdown(
                &mut rng,
                &credential,
                &state,
                nonce.as_bytes(),
            )?;
            system.verify(&state, &proof, nonce.as_bytes())?;
        }
        for measurement in 0..MEASUREMENTS {
            let nonce = format!("measure/{cover_nodes}/{measurement}");
            let start = Instant::now();
            let (proof, breakdown) = system.benchmark_show_with_breakdown(
                &mut rng,
                &credential,
                &state,
                nonce.as_bytes(),
            )?;
            let show_ms = start.elapsed().as_secs_f64() * 1_000.0;
            let start = Instant::now();
            let verified = system.verify(&state, &proof, nonce.as_bytes()).is_ok();
            let verify_ms = start.elapsed().as_secs_f64() * 1_000.0;
            writer.serialize(Rq3Row {
                scheme: "HiddenCover",
                cover_nodes,
                padded_set_size: cover_nodes.max(4).next_power_of_two(),
                measurement,
                presentation_bytes: proof.size_bytes(),
                show_ms,
                verify_ms,
                state_check_ms: breakdown.state_check_ms,
                match_ms: breakdown.match_ms,
                credential_bridge_ms: breakdown.credential_bridge_ms,
                cover_transform_ms: breakdown.cover_transform_ms,
                oom_ms: breakdown.oom_ms,
                verified,
            })?;
        }
    }
    writer.flush()?;
    Ok(())
}

fn benchmark_credentials(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = Writer::from_path(path)?;
    for depth in [10usize, 12, 14, 16, 18, 20] {
        for measurement in 0..MEASUREMENTS {
            let mut rng =
                ChaCha20Rng::seed_from_u64(0x7404_0000 + depth as u64 * 101 + measurement as u64);
            let start = Instant::now();
            let mut system = HiddenCover::setup(depth, &mut rng)?;
            let setup_ms = start.elapsed().as_secs_f64() * 1_000.0;
            let start = Instant::now();
            let credential = system.issue(&mut rng)?;
            let issue_ms = start.elapsed().as_secs_f64() * 1_000.0;
            writer.serialize(CredentialRow {
                depth,
                capacity: system.capacity(),
                measurement,
                setup_ms,
                issue_ms,
                credential_bytes: credential.size_bytes(),
                path_signatures: credential.path.len(),
            })?;
        }
    }
    writer.flush()?;
    Ok(())
}

fn workload(capacity: usize, count: usize, distribution: &str, seed: u64) -> Vec<usize> {
    assert!(count <= capacity);
    let mut rng = ChaCha20Rng::seed_from_u64(
        0xC0FE_E000 ^ capacity as u64 ^ (count as u64).rotate_left(17) ^ seed,
    );
    match distribution {
        "clustered" => {
            let start = rng.gen_range(0..=capacity - count);
            (start..start + count).collect()
        }
        "dispersed" => {
            let offset = rng.gen_range(0..capacity);
            (0..count)
                .map(|i| (offset + i * capacity / count) % capacity)
                .collect()
        }
        "random" => sample(&mut rng, capacity, count).into_vec(),
        _ => unreachable!(),
    }
}
