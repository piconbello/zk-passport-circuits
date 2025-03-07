import { Bytes, Field, Proof, VerificationKey, ZkProgram } from "o1js";
import { ProofCache } from "./proofCache";
import path from "node:path";
import { DigestDG1 } from "../circuits/bimodal/digestDG1";
import { DG1_TD3, LDS_256, SIGNED_ATTRS_256 } from "../circuits/constants";
import { time } from "./timer";
import type { Out } from "../circuits/bimodal/common.ts";
import {
  DigestLDS,
  LDS_DIGEST_BLOCKS_PER_ITERATION,
  LdsDigestState,
} from "../circuits/bimodal/digestLDS.ts";
import { DynamicSHA2 } from "@egemengol/mina-credentials";
import { sha256 } from "@noble/hashes/sha256";
import { DigestSignedAttrs } from "../circuits/bimodal/digestSignedAttrs.ts";

function vkToJSON(vk: VerificationKey): string {
  return JSON.stringify({
    hash: vk.hash.toJSON(),
    data: vk.data,
  });
}

function vkFromJSON(json: string): VerificationKey {
  const parsed = JSON.parse(json);

  return {
    hash: Field.fromJSON(parsed.hash),
    data: parsed.data,
  };
}

export async function getLeafDG1(cache: ProofCache, dg1: Uint8Array) {
  async function generate() {
    const compiled = await time("Compiling DigestDG1", async () => {
      return await DigestDG1.compile();
    });

    const { proof } = await time("Proving DigestDG1", async () => {
      return await DigestDG1.td3_256(DG1_TD3.from(dg1));
    });

    return {
      proofJSON: JSON.stringify(proof.toJSON()),
      verificationKeyJSON: vkToJSON(compiled.verificationKey),
    };
  }

  const { proofJSON, verificationKeyJSON } = await cache.getProof(
    path.resolve(__dirname, "../circuits/bimodal/digestDG1.ts"),
    dg1,
    generate,
  );
  const proof: Proof<undefined, Out> = await ZkProgram.Proof(
    DigestDG1,
  ).fromJSON(JSON.parse(proofJSON));
  const vk = vkFromJSON(verificationKeyJSON);
  return { proof, vk };
}

export async function getLeafLDS(
  cache: ProofCache,
  dg1: Uint8Array,
  lds: Uint8Array,
) {
  async function generate() {
    const compiled = await time("Compiling DigestLDS", async () => {
      return await DigestLDS.compile();
    });

    const { iterations, final } = DynamicSHA2.split(
      256,
      LDS_DIGEST_BLOCKS_PER_ITERATION,
      LDS_256.fromBytes(lds),
    );

    let curProof = await time("Proving DigestLDS init", async () => {
      return (await DigestLDS.init_256()).proof;
    });
    let curState = new LdsDigestState(LdsDigestState.initial());

    for (const [index, iter] of iterations.entries()) {
      curProof = await time(`Proving DigestLDS step ${index}`, async () => {
        return (await DigestLDS.step_256(curProof, curState, iter)).proof;
      });
      curState = new LdsDigestState(DynamicSHA2.update(curState, iter));
    }

    curProof = await time(`Proving DigestLDS final step`, async () => {
      return (await DigestLDS.step_final_256(curProof, curState, final)).proof;
    });
    curState = new LdsDigestState(DynamicSHA2.finalizeOnly(curState, final));

    const proofFinal = (
      await DigestLDS.finalize_256(
        curProof,
        curState,
        LDS_256.fromBytes(lds),
        Bytes.from(sha256(dg1)),
      )
    ).proof;

    console.log(proofFinal);

    return {
      proofJSON: JSON.stringify(proofFinal.toJSON()),
      verificationKeyJSON: vkToJSON(compiled.verificationKey),
    };
  }

  const { proofJSON, verificationKeyJSON } = await cache.getProof(
    path.resolve(__dirname, "../circuits/bimodal/digestLDS.ts"),
    Uint8Array.from(Array.from(dg1).concat(Array.from(lds))),
    generate,
  );
  const proof: Proof<undefined, Out> = await ZkProgram.Proof(
    DigestLDS,
  ).fromJSON(JSON.parse(proofJSON));
  const vk = vkFromJSON(verificationKeyJSON);
  return { proof, vk };
}

export async function getLeafSignedAttrs(
  cache: ProofCache,
  lds: Uint8Array,
  signedAttrs: Uint8Array,
) {
  async function generate() {
    const compiled = await time("Compiling DigestSignedAttrs", async () => {
      return await DigestSignedAttrs.compile();
    });

    const ldsDigest = Bytes.from(sha256(lds));

    const { proof } = await time("Proving DigestSignedAttrs", async () => {
      return await DigestSignedAttrs._256(
        ldsDigest,
        SIGNED_ATTRS_256.from(signedAttrs),
      );
    });

    return {
      proofJSON: JSON.stringify(proof.toJSON()),
      verificationKeyJSON: vkToJSON(compiled.verificationKey),
    };
  }

  const { proofJSON, verificationKeyJSON } = await cache.getProof(
    path.resolve(__dirname, "../circuits/bimodal/digestSignedAttrs.ts"),
    Uint8Array.from(Array.from(sha256(lds)).concat(Array.from(signedAttrs))),
    generate,
  );

  const proof: Proof<undefined, Out> = await ZkProgram.Proof(
    DigestSignedAttrs,
  ).fromJSON(JSON.parse(proofJSON));

  const vk = vkFromJSON(verificationKeyJSON);
  return { proof, vk };
}
