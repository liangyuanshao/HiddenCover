//! Setup, Issue, Revoke, Show and Verify.
#![allow(non_snake_case)] // Keep protocol variables aligned with the specification.

use ark_bls12_381::{Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ed25519_dalek::{Signature as StateSignature, Signer, SigningKey, Verifier};
use rand::{CryptoRng, Rng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    io::{Cursor, Read},
    time::Instant,
};

use crate::{
    credential::{BbsSignature, CredentialIssuer, CredentialProof},
    oom::{OneOfManyProof, PedersenParams, ProofGens},
    tree::CompleteTree,
    Error,
};

#[derive(Clone, Debug)]
pub struct PathCredential {
    pub node_value: Fr,
    pub signature: BbsSignature,
}

#[derive(Clone, Debug)]
pub struct Credential {
    pub holder_secret: Fr,
    pub serial: Fr,
    pub leaf: usize,
    pub path: Vec<PathCredential>,
}

impl Credential {
    pub fn size_bytes(&self) -> usize {
        self.holder_secret.compressed_size()
            + self.serial.compressed_size()
            + core::mem::size_of::<usize>()
            + self
                .path
                .iter()
                .map(|entry| entry.node_value.compressed_size() + entry.signature.compressed_size())
                .sum::<usize>()
    }
}

#[derive(Clone, Debug)]
pub struct RevocationState {
    pub version: u64,
    pub cover: Vec<Fr>,
    pub digest: [u8; 32],
    pub signature: StateSignature,
}

impl RevocationState {
    pub fn size_bytes(&self) -> usize {
        self.to_bytes().len()
    }

    /// Canonical comparison-harness encoding: version, Cover length, Cover
    /// scalars, digest, and Ed25519 signature.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(112 + self.cover.len() * 32);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&(self.cover.len() as u64).to_le_bytes());
        for value in &self.cover {
            value
                .serialize_compressed(&mut bytes)
                .expect("vec write cannot fail");
        }
        bytes.extend_from_slice(&self.digest);
        bytes.extend_from_slice(&self.signature.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let mut word = [0u8; 8];
        cursor
            .read_exact(&mut word)
            .map_err(|_| Error::InvalidState)?;
        let version = u64::from_le_bytes(word);
        cursor
            .read_exact(&mut word)
            .map_err(|_| Error::InvalidState)?;
        let cover_len = u64::from_le_bytes(word) as usize;
        let expected = 112usize
            .checked_add(cover_len.checked_mul(32).ok_or(Error::InvalidState)?)
            .ok_or(Error::InvalidState)?;
        if bytes.len() != expected {
            return Err(Error::InvalidState);
        }
        let mut cover = Vec::with_capacity(cover_len);
        for _ in 0..cover_len {
            cover.push(Fr::deserialize_compressed(&mut cursor).map_err(|_| Error::InvalidState)?);
        }
        let mut digest = [0u8; 32];
        cursor
            .read_exact(&mut digest)
            .map_err(|_| Error::InvalidState)?;
        let mut signature_bytes = [0u8; 64];
        cursor
            .read_exact(&mut signature_bytes)
            .map_err(|_| Error::InvalidState)?;
        Ok(Self {
            version,
            cover,
            digest,
            signature: StateSignature::from_bytes(&signature_bytes),
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ShowBreakdown {
    pub state_check_ms: f64,
    pub match_ms: f64,
    pub credential_bridge_ms: f64,
    pub cover_transform_ms: f64,
    pub oom_ms: f64,
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct Presentation {
    pub version: u64,
    pub state_digest: [u8; 32],
    pub B: G1Affine,
    pub credential_proof: CredentialProof,
    pub cover_proof: OneOfManyProof,
}

impl Presentation {
    pub fn size_bytes(&self) -> usize {
        8 + 32
            + self.B.compressed_size()
            + self.credential_proof.size_bytes()
            + self.cover_proof.size_bytes()
    }
}

pub struct HiddenCover {
    tree: CompleteTree,
    sid: Fr,
    issuer: CredentialIssuer,
    pedersen: PedersenParams,
    state_signer: SigningKey,
    available_leaves: Vec<usize>,
    revoked: HashSet<usize>,
    serial_to_leaf: HashMap<Vec<u8>, usize>,
    latest_state: RevocationState,
    accepted_nonces: HashSet<[u8; 32]>,
}

impl HiddenCover {
    pub fn setup<R: RngCore + CryptoRng>(depth: usize, rng: &mut R) -> crate::Result<Self> {
        let tree = CompleteTree::new(depth)?;
        let sid = Fr::rand(rng);
        let issuer = CredentialIssuer::setup(rng);
        let pedersen = PedersenParams::transparent();
        let state_signer = SigningKey::generate(rng);
        let available_leaves = (0..tree.capacity()).collect();
        let mut system = Self {
            tree,
            sid,
            issuer,
            pedersen,
            state_signer,
            available_leaves,
            revoked: HashSet::new(),
            serial_to_leaf: HashMap::new(),
            latest_state: RevocationState {
                version: 0,
                cover: Vec::new(),
                digest: [0u8; 32],
                signature: StateSignature::from_bytes(&[0u8; 64]),
            },
            accepted_nonces: HashSet::new(),
        };
        system.latest_state = system.make_state(0)?;
        Ok(system)
    }

    pub fn depth(&self) -> usize {
        self.tree.depth()
    }

    pub fn capacity(&self) -> usize {
        self.tree.capacity()
    }

    pub fn state(&self) -> RevocationState {
        self.latest_state.clone()
    }

    pub fn issue<R: RngCore>(&mut self, rng: &mut R) -> crate::Result<Credential> {
        if self.available_leaves.is_empty() {
            return Err(Error::CapacityExhausted);
        }
        let index = rng.gen_range(0..self.available_leaves.len());
        let leaf = self.available_leaves.swap_remove(index);
        let holder_secret = Fr::rand(rng);
        let serial = Fr::rand(rng);
        let mut path = Vec::with_capacity(self.tree.depth() + 1);
        for node in self.tree.path(leaf)? {
            let node_value = encode_node(self.sid, node);
            let signature = self
                .issuer
                .sign(rng, self.sid, holder_secret, serial, node_value)?;
            path.push(PathCredential {
                node_value,
                signature,
            });
        }
        self.serial_to_leaf.insert(scalar_bytes(serial), leaf);
        Ok(Credential {
            holder_secret,
            serial,
            leaf,
            path,
        })
    }

    pub fn revoke(&mut self, serial: Fr) -> crate::Result<RevocationState> {
        let leaf = *self
            .serial_to_leaf
            .get(&scalar_bytes(serial))
            .ok_or(Error::UnknownCredential)?;
        if !self.revoked.insert(leaf) {
            return Err(Error::UnknownCredential);
        }
        let version = self.latest_state.version + 1;
        self.latest_state = self.make_state(version)?;
        Ok(self.latest_state.clone())
    }

    /// Benchmark-only workload loader.  It emulates a revocation history at
    /// the leaf layer without paying for issuing every unrelated credential.
    /// It is not part of the five protocol algorithms.
    #[doc(hidden)]
    pub fn benchmark_replace_revoked(
        &mut self,
        leaves: impl IntoIterator<Item = usize>,
    ) -> crate::Result<RevocationState> {
        let next: HashSet<usize> = leaves.into_iter().collect();
        if next.iter().any(|leaf| *leaf >= self.tree.capacity()) {
            return Err(Error::InvalidTree);
        }
        self.revoked = next;
        let version = self.latest_state.version + 1;
        self.latest_state = self.make_state(version)?;
        Ok(self.latest_state.clone())
    }

    /// Benchmark-only exact-size authenticated Cover. The caller must include
    /// one node from the issued credential path when measuring a valid Show.
    #[doc(hidden)]
    pub fn benchmark_replace_cover(&mut self, cover: Vec<Fr>) -> RevocationState {
        let version = self.latest_state.version + 1;
        let digest = state_digest(self.sid, version, &cover);
        let signature = self.state_signer.sign(&digest);
        self.latest_state = RevocationState {
            version,
            cover,
            digest,
            signature,
        };
        self.latest_state.clone()
    }

    #[doc(hidden)]
    pub fn benchmark_check_state(&self, state: &RevocationState) -> crate::Result<()> {
        self.check_state(state)
    }

    /// Same protocol proof as show, with non-overlapping timing components for
    /// the experimental bottleneck analysis.
    #[doc(hidden)]
    pub fn benchmark_show_with_breakdown<R: RngCore>(
        &self,
        rng: &mut R,
        credential: &Credential,
        state: &RevocationState,
        nonce: &[u8],
    ) -> crate::Result<(Presentation, ShowBreakdown)> {
        let start = Instant::now();
        self.check_state(state)?;
        let state_check_ms = start.elapsed().as_secs_f64() * 1_000.0;

        let start = Instant::now();
        let path_index = credential
            .path
            .iter()
            .position(|entry| state.cover.contains(&entry.node_value))
            .ok_or(Error::Revoked)?;
        let cover_index = state
            .cover
            .iter()
            .position(|value| *value == credential.path[path_index].node_value)
            .ok_or(Error::Revoked)?;
        let match_ms = start.elapsed().as_secs_f64() * 1_000.0;

        let ad = presentation_ad(self.sid, state, nonce);
        let entry = &credential.path[path_index];
        let start = Instant::now();
        let (B, opening, credential_proof) = self.issuer.prove(
            rng,
            &self.pedersen,
            self.sid,
            credential.holder_secret,
            credential.serial,
            entry.node_value,
            &entry.signature,
            &ad,
        )?;
        let credential_bridge_ms = start.elapsed().as_secs_f64() * 1_000.0;

        let start = Instant::now();
        let set = self.cover_commitments(B, &state.cover);
        let n_bits = set.len().ilog2() as usize;
        let gens = ProofGens::new(n_bits, &self.pedersen)?;
        let cover_transform_ms = start.elapsed().as_secs_f64() * 1_000.0;

        let start = Instant::now();
        let cover_proof = gens.prove(rng, &set, cover_index, opening, &ad)?;
        let oom_ms = start.elapsed().as_secs_f64() * 1_000.0;
        Ok((
            Presentation {
                version: state.version,
                state_digest: state.digest,
                B,
                credential_proof,
                cover_proof,
            },
            ShowBreakdown {
                state_check_ms,
                match_ms,
                credential_bridge_ms,
                cover_transform_ms,
                oom_ms,
            },
        ))
    }

    pub fn show<R: RngCore>(
        &self,
        rng: &mut R,
        credential: &Credential,
        state: &RevocationState,
        nonce: &[u8],
    ) -> crate::Result<Presentation> {
        self.check_state(state)?;
        let path_index = credential
            .path
            .iter()
            .position(|entry| state.cover.contains(&entry.node_value))
            .ok_or(Error::Revoked)?;
        let cover_index = state
            .cover
            .iter()
            .position(|value| *value == credential.path[path_index].node_value)
            .ok_or(Error::Revoked)?;
        let ad = presentation_ad(self.sid, state, nonce);
        let entry = &credential.path[path_index];
        let (B, opening, credential_proof) = self.issuer.prove(
            rng,
            &self.pedersen,
            self.sid,
            credential.holder_secret,
            credential.serial,
            entry.node_value,
            &entry.signature,
            &ad,
        )?;
        let set = self.cover_commitments(B, &state.cover);
        let n_bits = set.len().ilog2() as usize;
        let gens = ProofGens::new(n_bits, &self.pedersen)?;
        let cover_proof = gens.prove(rng, &set, cover_index, opening, &ad)?;
        Ok(Presentation {
            version: state.version,
            state_digest: state.digest,
            B,
            credential_proof,
            cover_proof,
        })
    }

    pub fn verify(
        &mut self,
        state: &RevocationState,
        presentation: &Presentation,
        nonce: &[u8],
    ) -> crate::Result<()> {
        self.check_state(state)?;
        if presentation.version != state.version || presentation.state_digest != state.digest {
            return Err(Error::InvalidState);
        }
        let nonce_key: [u8; 32] = Sha256::digest(nonce).into();
        if self.accepted_nonces.contains(&nonce_key) {
            return Err(Error::Replay);
        }
        let ad = presentation_ad(self.sid, state, nonce);
        self.issuer.verify_proof(
            &self.pedersen,
            self.sid,
            &presentation.B,
            &presentation.credential_proof,
            &ad,
        )?;
        let set = self.cover_commitments(presentation.B, &state.cover);
        let n_bits = set.len().ilog2() as usize;
        let gens = ProofGens::new(n_bits, &self.pedersen)?;
        gens.verify(&set, &presentation.cover_proof, &ad)?;
        self.accepted_nonces.insert(nonce_key);
        Ok(())
    }

    fn make_state(&self, version: u64) -> crate::Result<RevocationState> {
        let nodes = self.tree.cover(&self.revoked)?;
        let cover: Vec<Fr> = nodes
            .into_iter()
            .map(|node| encode_node(self.sid, node))
            .collect();
        let digest = state_digest(self.sid, version, &cover);
        let signature = self.state_signer.sign(&digest);
        Ok(RevocationState {
            version,
            cover,
            digest,
            signature,
        })
    }

    fn check_state(&self, state: &RevocationState) -> crate::Result<()> {
        if state.version != self.latest_state.version || state.digest != self.latest_state.digest {
            return Err(Error::InvalidState);
        }
        let digest = state_digest(self.sid, state.version, &state.cover);
        if digest != state.digest
            || self
                .state_signer
                .verifying_key()
                .verify(&digest, &state.signature)
                .is_err()
        {
            return Err(Error::InvalidState);
        }
        Ok(())
    }

    fn cover_commitments(&self, B: G1Affine, cover: &[Fr]) -> Vec<G1Affine> {
        let target_len = cover.len().max(4).next_power_of_two();
        let mut set: Vec<G1Affine> = cover
            .iter()
            .map(|value| {
                (B.into_group() - self.pedersen.h.mul_bigint(value.into_bigint())).into_affine()
            })
            .collect();
        // The public padding point is Com(1;0)=h.  Selecting it would require
        // knowledge of log_g(h), so it cannot provide a forged zero opening.
        set.resize(target_len, self.pedersen.h);
        set
    }
}

fn encode_node(sid: Fr, node: usize) -> Fr {
    let mut h = Sha256::new();
    h.update(b"HiddenCover.Node.v1");
    h.update(scalar_bytes(sid));
    h.update((node as u64).to_le_bytes());
    Fr::from_le_bytes_mod_order(&h.finalize())
}

fn scalar_bytes(value: Fr) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).expect("vec write");
    bytes
}

fn state_digest(sid: Fr, version: u64, cover: &[Fr]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"HiddenCover.State.v1");
    h.update(scalar_bytes(sid));
    h.update(version.to_le_bytes());
    h.update((cover.len() as u64).to_le_bytes());
    for value in cover {
        h.update(scalar_bytes(*value));
    }
    h.finalize().into()
}

fn presentation_ad(sid: Fr, state: &RevocationState, nonce: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"HiddenCover.Show.v1");
    bytes.extend_from_slice(&scalar_bytes(sid));
    bytes.extend_from_slice(&state.version.to_le_bytes());
    bytes.extend_from_slice(&state.digest);
    bytes.extend_from_slice(&(nonce.len() as u64).to_le_bytes());
    bytes.extend_from_slice(nonce);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    fn setup_with_two() -> (HiddenCover, Credential, Credential, ChaCha20Rng) {
        let mut rng = ChaCha20Rng::seed_from_u64(99);
        let mut system = HiddenCover::setup(4, &mut rng).unwrap();
        let a = system.issue(&mut rng).unwrap();
        let b = system.issue(&mut rng).unwrap();
        (system, a, b, rng)
    }

    #[test]
    fn valid_presentation_and_replay_rejection() {
        let (mut system, a, _, mut rng) = setup_with_two();
        let state = system.state();
        assert_eq!(state.cover.len(), 1);
        let proof = system.show(&mut rng, &a, &state, b"nonce-1").unwrap();
        system.verify(&state, &proof, b"nonce-1").unwrap();
        assert!(matches!(
            system.verify(&state, &proof, b"nonce-1"),
            Err(Error::Replay)
        ));
    }

    #[test]
    fn revoked_holder_and_stale_state_fail() {
        let (mut system, a, b, mut rng) = setup_with_two();
        let old = system.state();
        let old_proof = system.show(&mut rng, &a, &old, b"old").unwrap();
        let fresh = system.revoke(a.serial).unwrap();
        assert!(matches!(
            system.show(&mut rng, &a, &fresh, b"new"),
            Err(Error::Revoked)
        ));
        assert!(matches!(
            system.verify(&old, &old_proof, b"old"),
            Err(Error::InvalidState)
        ));
        let live = system.show(&mut rng, &b, &fresh, b"live").unwrap();
        system.verify(&fresh, &live, b"live").unwrap();
    }

    #[test]
    fn bridge_state_and_cover_mutations_fail() {
        let (mut system, a, _, mut rng) = setup_with_two();
        let state = system.state();
        let mut proof = system.show(&mut rng, &a, &state, b"mutate").unwrap();
        proof.B = system
            .pedersen
            .commit(Fr::rand(&mut rng), Fr::rand(&mut rng));
        assert!(system.verify(&state, &proof, b"mutate").is_err());

        let proof = system.show(&mut rng, &a, &state, b"state").unwrap();
        let mut altered = state.clone();
        altered.cover[0] = Fr::rand(&mut rng);
        assert!(matches!(
            system.verify(&altered, &proof, b"state"),
            Err(Error::InvalidState)
        ));
    }

    #[test]
    fn revocation_state_round_trip() {
        let (system, _, _, _) = setup_with_two();
        let state = system.state();
        let encoded = state.to_bytes();
        let decoded = RevocationState::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.version, state.version);
        assert_eq!(decoded.cover, state.cover);
        assert_eq!(decoded.digest, state.digest);
        assert_eq!(decoded.signature.to_bytes(), state.signature.to_bytes());
        assert_eq!(encoded.len(), 112 + 32 * state.cover.len());
    }
}
