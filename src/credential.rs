//! BBS credential signatures and the shared-response bridge proof.
#![allow(non_snake_case)] // Keep protocol variables aligned with the specification.

use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use bbs_plus::{
    proof_23_ietf::{PoKOfSignature23G1Proof, PoKOfSignature23G1Protocol},
    setup::{KeypairG2, PublicKeyG2, SignatureParams23G1},
    signature_23::Signature23G1,
};
use blake2::Blake2b512;
use dock_crypto_utils::signature::MessageOrBlinding;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::{oom::PedersenParams, Error};

pub type BbsSignature = Signature23G1<Bls12_381>;

#[derive(Clone, Debug)]
pub struct CredentialIssuer {
    pub params: SignatureParams23G1<Bls12_381>,
    pub keypair: KeypairG2<Bls12_381>,
}

impl CredentialIssuer {
    pub fn setup<R: RngCore>(rng: &mut R) -> Self {
        let params = SignatureParams23G1::<Bls12_381>::new::<Blake2b512>(b"HiddenCover.BBS.v1", 4);
        let keypair = KeypairG2::<Bls12_381>::generate_using_rng_and_bbs23_params(rng, &params);
        Self { params, keypair }
    }

    pub fn public_key(&self) -> &PublicKeyG2<Bls12_381> {
        &self.keypair.public_key
    }

    pub fn sign<R: RngCore>(
        &self,
        rng: &mut R,
        sid: Fr,
        holder_secret: Fr,
        serial: Fr,
        node: Fr,
    ) -> crate::Result<BbsSignature> {
        let messages = [sid, holder_secret, serial, node];
        BbsSignature::new(rng, &messages, &self.keypair.secret_key, &self.params)
            .map_err(|_| Error::Verification)
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct CredentialProof {
    pub(crate) bbs: PoKOfSignature23G1Proof<Bls12_381>,
    pub(crate) T_com: G1Affine,
    pub(crate) x_response: Fr,
    pub(crate) r_response: Fr,
}

impl CredentialProof {
    pub fn size_bytes(&self) -> usize {
        self.bbs.compressed_size()
            + self.T_com.compressed_size()
            + self.x_response.compressed_size()
            + self.r_response.compressed_size()
    }
}

impl CredentialIssuer {
    /// Prove possession of a BBS signature while sharing the hidden node
    /// response with the Pedersen commitment `B = g*r + h*x`.
    #[allow(clippy::too_many_arguments)] // Mirrors the protocol statement and witness.
    pub fn prove<R: RngCore>(
        &self,
        rng: &mut R,
        pedersen: &PedersenParams,
        sid: Fr,
        holder_secret: Fr,
        serial: Fr,
        node: Fr,
        signature: &BbsSignature,
        ad: &[u8],
    ) -> crate::Result<(G1Affine, Fr, CredentialProof)> {
        let r = Fr::rand(rng);
        let x_blinding = Fr::rand(rng);
        let r_blinding = Fr::rand(rng);
        let B = pedersen.commit(node, r);
        let T_com = pedersen.commit(x_blinding, r_blinding);

        let messages = [
            MessageOrBlinding::RevealMessage(&sid),
            MessageOrBlinding::BlindMessageRandomly(&holder_secret),
            MessageOrBlinding::BlindMessageRandomly(&serial),
            MessageOrBlinding::BlindMessageWithConcreteBlinding {
                message: &node,
                blinding: x_blinding,
            },
        ];
        let protocol = PoKOfSignature23G1Protocol::init(rng, signature, &self.params, messages)
            .map_err(|_| Error::Verification)?;
        let revealed = BTreeMap::from([(0usize, sid)]);
        let mut bytes = Vec::new();
        protocol
            .challenge_contribution(&revealed, &self.params, &mut bytes)
            .map_err(|_| Error::Verification)?;
        append_joint_statement(&mut bytes, self.public_key(), &B, &T_com, ad);
        let challenge = hash_to_scalar(&bytes);
        let revealed_ids = BTreeSet::from([0usize]);
        let skipped_ids = BTreeSet::from([3usize]);
        let bbs = protocol
            .gen_partial_proof(&challenge, &revealed_ids, &skipped_ids)
            .map_err(|_| Error::Verification)?;
        Ok((
            B,
            r,
            CredentialProof {
                bbs,
                T_com,
                x_response: x_blinding + challenge * node,
                r_response: r_blinding + challenge * r,
            },
        ))
    }

    pub fn verify_proof(
        &self,
        pedersen: &PedersenParams,
        sid: Fr,
        B: &G1Affine,
        proof: &CredentialProof,
        ad: &[u8],
    ) -> crate::Result<()> {
        let revealed = BTreeMap::from([(0usize, sid)]);
        let mut bytes = Vec::new();
        proof
            .bbs
            .challenge_contribution(&revealed, &self.params, &mut bytes)
            .map_err(|_| Error::Verification)?;
        append_joint_statement(&mut bytes, self.public_key(), B, &proof.T_com, ad);
        let challenge = hash_to_scalar(&bytes);
        proof
            .bbs
            .verify_partial(
                &revealed,
                &challenge,
                self.public_key().clone(),
                self.params.clone(),
                BTreeMap::from([(3usize, proof.x_response)]),
            )
            .map_err(|_| Error::Verification)?;

        let lhs = pedersen.g.mul_bigint(proof.r_response.into_bigint())
            + pedersen.h.mul_bigint(proof.x_response.into_bigint())
            - B.mul_bigint(challenge.into_bigint());
        if lhs.into_affine() != proof.T_com {
            return Err(Error::Verification);
        }
        Ok(())
    }
}

fn append_joint_statement(
    bytes: &mut Vec<u8>,
    public_key: &PublicKeyG2<Bls12_381>,
    B: &G1Affine,
    T_com: &G1Affine,
    ad: &[u8],
) {
    bytes.extend_from_slice(b"HiddenCover.CredentialBridge.v1");
    public_key
        .serialize_compressed(&mut *bytes)
        .expect("vec write");
    B.serialize_compressed(&mut *bytes).expect("vec write");
    T_com.serialize_compressed(&mut *bytes).expect("vec write");
    bytes.extend_from_slice(&(ad.len() as u64).to_le_bytes());
    bytes.extend_from_slice(ad);
}

fn hash_to_scalar(bytes: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(&Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    #[test]
    fn shared_response_binds_bbs_node_to_pedersen_commitment() {
        let mut rng = ChaCha20Rng::seed_from_u64(10);
        let issuer = CredentialIssuer::setup(&mut rng);
        let pedersen = PedersenParams::transparent();
        let sid = Fr::rand(&mut rng);
        let u = Fr::rand(&mut rng);
        let sn = Fr::rand(&mut rng);
        let x = Fr::rand(&mut rng);
        let signature = issuer.sign(&mut rng, sid, u, sn, x).unwrap();
        let (B, _, proof) = issuer
            .prove(&mut rng, &pedersen, sid, u, sn, x, &signature, b"ad")
            .unwrap();
        issuer
            .verify_proof(&pedersen, sid, &B, &proof, b"ad")
            .unwrap();
        assert!(issuer
            .verify_proof(&pedersen, sid, &B, &proof, b"wrong-ad")
            .is_err());
    }
}
