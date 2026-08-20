//! Groth--Kohlweiss one-out-of-many proof over BLS12-381.
#![allow(non_snake_case)] // Keep protocol variables aligned with the specification.
//!
//! The algorithmic structure is adapted from the MIT-licensed
//! `phreaknik/one-of-many-proofs` implementation.  We deliberately port it
//! from Ristretto to the BLS12-381 scalar field used by the BBS proof.  This
//! research implementation is not security audited.

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bbs_plus::setup::SignatureParams23G1;
use blake2::Blake2b512;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::Error;

#[derive(Clone, Debug)]
pub struct PedersenParams {
    pub g: G1Affine,
    pub h: G1Affine,
}

impl PedersenParams {
    pub fn transparent() -> Self {
        let params =
            SignatureParams23G1::<Bls12_381>::new::<Blake2b512>(b"HiddenCover.Pedersen.v1", 1);
        Self {
            g: params.g1,
            h: params.h[0],
        }
    }

    pub fn commit(&self, value: Fr, blinding: Fr) -> G1Affine {
        (self.g.mul_bigint(blinding.into_bigint()) + self.h.mul_bigint(value.into_bigint()))
            .into_affine()
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct ProofGens {
    pub n_bits: usize,
    pub G: G1Affine,
    pub H: Vec<G1Affine>,
}

impl ProofGens {
    pub fn new(n_bits: usize, pedersen: &PedersenParams) -> crate::Result<Self> {
        if !(2..=24).contains(&n_bits) {
            return Err(Error::MalformedProof);
        }
        let label = format!("HiddenCover.OoM.H.v1/{n_bits}");
        let params = SignatureParams23G1::<Bls12_381>::new::<Blake2b512>(
            label.as_bytes(),
            (2 * n_bits) as u32,
        );
        Ok(Self {
            n_bits,
            G: pedersen.g,
            H: params.h,
        })
    }

    pub fn set_size(&self) -> usize {
        1usize << self.n_bits
    }

    fn vector_commit(&self, values: impl Iterator<Item = Fr>, r: Fr) -> crate::Result<G1Affine> {
        let mut c = self.G.mul_bigint(r.into_bigint());
        for (i, value) in values.enumerate() {
            let h = self.H.get(i).ok_or(Error::MalformedProof)?;
            c += h.mul_bigint(value.into_bigint());
        }
        Ok(c.into_affine())
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct BitProof {
    A: G1Affine,
    C: G1Affine,
    D: G1Affine,
    f1_j: Vec<Fr>,
    z_A: Fr,
    z_C: Fr,
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct OneOfManyProof {
    B: G1Affine,
    bit_proof: BitProof,
    G_k: Vec<G1Affine>,
    z: Fr,
}

impl OneOfManyProof {
    pub fn size_bytes(&self) -> usize {
        self.compressed_size()
    }
}

#[derive(Clone)]
struct Transcript {
    bytes: Vec<u8>,
}

impl Transcript {
    fn statement(n_bits: usize, ad: &[u8], set: &[G1Affine]) -> Self {
        let mut t = Self { bytes: Vec::new() };
        t.append_bytes(b"HiddenCover.GK-OoM.v1");
        t.append_u64(n_bits as u64);
        t.append_bytes(ad);
        t.append_u64(set.len() as u64);
        for point in set {
            t.append_point(point);
        }
        t
    }

    fn append_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn append_bytes(&mut self, value: &[u8]) {
        self.append_u64(value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    fn append_point(&mut self, point: &G1Affine) {
        point
            .serialize_compressed(&mut self.bytes)
            .expect("vec write");
    }

    fn challenge(&self, label: &[u8]) -> Fr {
        let mut h = Sha256::new();
        h.update(&self.bytes);
        h.update((label.len() as u64).to_le_bytes());
        h.update(label);
        Fr::from_le_bytes_mod_order(&h.finalize())
    }
}

impl ProofGens {
    pub fn prove<R: RngCore>(
        &self,
        rng: &mut R,
        set: &[G1Affine],
        index: usize,
        opening: Fr,
        ad: &[u8],
    ) -> crate::Result<OneOfManyProof> {
        if set.len() != self.set_size() || index >= set.len() {
            return Err(Error::MalformedProof);
        }
        let mut transcript = Transcript::statement(self.n_bits, ad, set);
        let rho_k: Vec<Fr> = (0..self.n_bits).map(|_| Fr::rand(rng)).collect();
        let a_j: Vec<Fr> = (0..self.n_bits).map(|_| Fr::rand(rng)).collect();
        let a_j_i = [a_j.clone(), a_j.iter().map(|a| -*a).collect::<Vec<_>>()];

        let mut gk: Vec<G1Projective> = rho_k
            .iter()
            .map(|rho| self.G.mul_bigint(rho.into_bigint()))
            .collect();
        let gray_index = gray_code(index);
        for (i, commitment) in set.iter().enumerate() {
            let p_i = compute_p_i(gray_code(i), gray_index, &a_j_i);
            for (k, coefficient) in p_i.iter().enumerate() {
                gk[k] += commitment.mul_bigint(coefficient.into_bigint());
            }
        }
        let G_k = G1Projective::normalize_batch(&gk);
        for point in &G_k {
            transcript.append_point(point);
        }

        let (B, bit_proof, x) = self.commit_bits(rng, &transcript, gray_index, &a_j)?;
        let z = opening * pow(x, self.n_bits) - poly_eval(&rho_k, x);
        Ok(OneOfManyProof {
            B,
            bit_proof,
            G_k,
            z,
        })
    }

    pub fn verify(&self, set: &[G1Affine], proof: &OneOfManyProof, ad: &[u8]) -> crate::Result<()> {
        if set.len() != self.set_size()
            || proof.G_k.len() != self.n_bits
            || proof.bit_proof.f1_j.len() != self.n_bits
        {
            return Err(Error::MalformedProof);
        }
        let mut transcript = Transcript::statement(self.n_bits, ad, set);
        for point in &proof.G_k {
            transcript.append_point(point);
        }
        let x = self.verify_bits(&transcript, &proof.B, &proof.bit_proof)?;

        let mut C = G1Projective::zero();
        for (i, commitment) in set.iter().enumerate() {
            let gray = gray_code(i);
            let mut coeff = Fr::one();
            for j in 0..self.n_bits {
                let f1 = proof.bit_proof.f1_j[j];
                coeff *= if bit(gray, j) == 1 { f1 } else { x - f1 };
            }
            C += commitment.mul_bigint(coeff.into_bigint());
        }
        let E = self.G.mul_bigint(proof.z.into_bigint());
        let mut G = G1Projective::zero();
        let mut xk = Fr::one();
        for point in &proof.G_k {
            G += point.mul_bigint(xk.into_bigint());
            xk *= x;
        }
        if C != E + G {
            return Err(Error::Verification);
        }
        Ok(())
    }

    fn commit_bits<R: RngCore>(
        &self,
        rng: &mut R,
        base: &Transcript,
        index: usize,
        a_j: &[Fr],
    ) -> crate::Result<(G1Affine, BitProof, Fr)> {
        let bits = (0..2)
            .map(|i| {
                (0..self.n_bits)
                    .map(|j| Fr::from((bit(index, j) == i) as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let a = [a_j.to_vec(), a_j.iter().map(|v| -*v).collect::<Vec<_>>()];
        let r_A = Fr::rand(rng);
        let r_B = Fr::rand(rng);
        let r_C = Fr::rand(rng);
        let r_D = Fr::rand(rng);
        let A = self.vector_commit(a.iter().flatten().copied(), r_A)?;
        let B = self.vector_commit(bits.iter().flatten().copied(), r_B)?;
        let C = self.vector_commit(
            a.iter()
                .flatten()
                .zip(bits.iter().flatten())
                .map(|(aa, bb)| *aa * (Fr::one() - Fr::from(2u64) * bb)),
            r_C,
        )?;
        let D = self.vector_commit(a.iter().flatten().map(|aa| -(*aa * aa)), r_D)?;
        let mut t = base.clone();
        for point in [&A, &B, &C, &D] {
            t.append_point(point);
        }
        let x = t.challenge(b"bit-proof-challenge");
        let f1_j = a[1]
            .iter()
            .zip(bits[1].iter())
            .map(|(aa, bb)| *bb * x + aa)
            .collect();
        Ok((
            B,
            BitProof {
                A,
                C,
                D,
                f1_j,
                z_A: r_B * x + r_A,
                z_C: r_C * x + r_D,
            },
            x,
        ))
    }

    fn verify_bits(&self, base: &Transcript, B: &G1Affine, proof: &BitProof) -> crate::Result<Fr> {
        let mut t = base.clone();
        for point in [&proof.A, B, &proof.C, &proof.D] {
            t.append_point(point);
        }
        let x = t.challenge(b"bit-proof-challenge");
        let f0: Vec<Fr> = proof.bit_proof_f0(x);
        let f = [f0, proof.f1_j.clone()];
        let rhs1 = self.vector_commit(f.iter().flatten().copied(), proof.z_A)?;
        let lhs1 = (B.mul_bigint(x.into_bigint()) + proof.A).into_affine();
        if lhs1 != rhs1 {
            return Err(Error::Verification);
        }
        let rhs2 = self.vector_commit(f.iter().flatten().map(|v| *v * (x - v)), proof.z_C)?;
        let lhs2 = (proof.C.mul_bigint(x.into_bigint()) + proof.D).into_affine();
        if lhs2 != rhs2 {
            return Err(Error::Verification);
        }
        Ok(x)
    }
}

impl BitProof {
    fn bit_proof_f0(&self, x: Fr) -> Vec<Fr> {
        self.f1_j.iter().map(|f| x - f).collect()
    }
}

fn compute_p_i(i: usize, l: usize, a: &[Vec<Fr>; 2]) -> Vec<Fr> {
    let n = a[0].len();
    let mut p = vec![Fr::one()];
    for j in 0..n {
        let constant = a[bit(i, j)][j];
        let linear = Fr::from((bit(l, j) == bit(i, j)) as u64);
        let mut next = vec![Fr::zero(); p.len() + 1];
        for (k, coefficient) in p.iter().enumerate() {
            next[k] += *coefficient * constant;
            next[k + 1] += *coefficient * linear;
        }
        p = next;
    }
    p.resize(n, Fr::zero());
    p.truncate(n);
    p
}

fn poly_eval(coefficients: &[Fr], x: Fr) -> Fr {
    coefficients
        .iter()
        .rev()
        .fold(Fr::zero(), |acc, coefficient| acc * x + coefficient)
}

fn pow(base: Fr, exponent: usize) -> Fr {
    (0..exponent).fold(Fr::one(), |acc, _| acc * base)
}

fn gray_code(n: usize) -> usize {
    n ^ (n >> 1)
}

fn bit(value: usize, j: usize) -> usize {
    (value >> j) & 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    #[test]
    fn proves_one_zero_commitment_and_rejects_mutation() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let pedersen = PedersenParams::transparent();
        let gens = ProofGens::new(4, &pedersen).unwrap();
        let index = 9;
        let opening = Fr::rand(&mut rng);
        let mut set: Vec<G1Affine> = (0..gens.set_size())
            .map(|_| pedersen.commit(Fr::rand(&mut rng), Fr::rand(&mut rng)))
            .collect();
        set[index] = pedersen.commit(Fr::zero(), opening);
        let proof = gens
            .prove(&mut rng, &set, index, opening, b"test-ad")
            .unwrap();
        gens.verify(&set, &proof, b"test-ad").unwrap();
        set[0] = pedersen.commit(Fr::rand(&mut rng), Fr::rand(&mut rng));
        assert!(gens.verify(&set, &proof, b"test-ad").is_err());
    }
}
