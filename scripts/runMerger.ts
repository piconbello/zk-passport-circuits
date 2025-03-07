import { DG1_Digest } from "../circuits/bimodal/digestDG1";
import {
  LDS_Digest,
  LDS_DIGEST_BLOCKS_PER_ITERATION,
  LdsDigestState,
  OFFSET_DG1_IN_LDS_256,
} from "../circuits/bimodal/digestLDS";
import { SignedAttrs_Digest } from "../circuits/bimodal/signedAttrsDigest";
import {
  Merger,
  NodeProofLeft,
  NodeProofRight,
} from "../circuits/bimodal/merger";
import fs from "node:fs";
import { parseBundle, type Bundle } from "../src/parseBundle";
import { DG1_TD3, LDS_256, SIGNED_ATTRS_256 } from "../circuits/constants";
import {
  DynamicBytes,
  DynamicSHA2,
  SHA2,
} from "@egemengol/mina-credentials/dynamic";
import type { Bytes, Field } from "o1js";
import { createHash } from "node:crypto";

let VKS: {
  dg1: {
    data: string;
    hash: Field;
  };
  lds: {
    data: string;
    hash: Field;
  };
  signedAttrs: {
    data: string;
    hash: Field;
  };
  merger: {
    data: string;
    hash: Field;
  };
} | null = null;

async function compile() {
  console.log("Compiling dg1");
  const vkDG1 = (await DG1_Digest.compile()).verificationKey;
  console.log("Compiling lds");
  const vkLDS = (await LDS_Digest.compile()).verificationKey;
  console.log("Compiling signedAttrs");
  const vkSignedAttrs = (await SignedAttrs_Digest.compile()).verificationKey;
  console.log("Compiling merger");
  const vkMerger = (await Merger.compile()).verificationKey;
  console.log("Compilation DONE");
  return {
    dg1: vkDG1,
    lds: vkLDS,
    signedAttrs: vkSignedAttrs,
    merger: vkMerger,
  };
}

async function proveLDS(
  lds: Uint8Array,
  dg1Digest: Bytes,
  status_callback: (status: string) => void = () => {
    /* noop as default */
  },
) {
  if (lds.length === 0) {
    throw Error("Empty payload is not permitted");
  }
  const { iterations, final } = DynamicSHA2.split(
    256,
    LDS_DIGEST_BLOCKS_PER_ITERATION,
    LDS_256.fromBytes(lds),
  );

  let curState = new LdsDigestState(LdsDigestState.initial());
  let curProof = (await LDS_Digest.init_256()).proof;
  status_callback("proved initial");

  for (const [index, iter] of iterations.entries()) {
    const proof = await LDS_Digest.step_256(curProof, curState, iter);
    curProof = proof.proof;
    curState = new LdsDigestState(DynamicSHA2.update(curState, iter));
    status_callback(`proved step ${index + 1}`);
  }

  curProof = (await LDS_Digest.step_final_256(curProof, curState, final)).proof;
  curState = new LdsDigestState(DynamicSHA2.finalizeOnly(curState, final));
  status_callback("proved step final");

  // here

  const proofFinal = (
    await LDS_Digest.finalize_256(
      curProof,
      curState,
      LDS_256.fromBytes(lds),
      dg1Digest,
    )
  ).proof;

  return proofFinal;
}

async function main() {
  const file = fs.readFileSync("files/bundle.frodo.256-256-r1.json", "utf-8");
  const bundle = parseBundle(file);

  VKS = await compile();

  console.log("proving dg1");
  const proofDG1 = (await DG1_Digest._256(DG1_TD3.from(bundle.dg1))).proof;

  console.log("proving lds");
  const dg1Digest: Bytes = SHA2.hash(256, bundle.dg1);

  const proofLDS = await proveLDS(bundle.lds, dg1Digest, console.log);

  console.log("proving signedattrs");
  const ldsDigest: Bytes = SHA2.hash(256, bundle.lds);
  const proofSignedAttrs = (
    await SignedAttrs_Digest._256(
      ldsDigest,
      SIGNED_ATTRS_256.from(bundle.signed_attrs),
    )
  ).proof;

  const dynDG1 = NodeProofLeft.fromProof(proofDG1);
  const dynLDS = NodeProofRight.fromProof(proofLDS);

  console.log(
    "DG1 proof structure:",
    JSON.stringify(proofDG1).substring(0, 200),
  );
  console.log(
    "LDS proof structure:",
    JSON.stringify(proofLDS).substring(0, 200),
  );

  console.log("VK DG1 hash:", VKS.dg1.hash.toString());
  console.log("VK LDS hash:", VKS.lds.hash.toString());

  console.log("Dynamic DG1 proof:", Object.keys(dynDG1));
  console.log("Dynamic LDS proof:", Object.keys(dynLDS));

  dynDG1.verify(VKS.dg1);
  dynLDS.verify(VKS.lds);

  const dynSignedAttrs = NodeProofRight.fromProof(proofSignedAttrs);
  dynLDS.verify(VKS.dg1); //this should fail

  console.log("merging dg1 and lds");
  const firstMergeProof = (await Merger.merge(dynDG1, VKS.dg1, dynLDS, VKS.lds))
    .proof;

  const dynFirstMerge = NodeProofLeft.fromProof(firstMergeProof);
  // const dynSignedAttrs = NodeProofRight.fromProof(proofSignedAttrs);

  console.log("merging first merge and signedattrs");
  const mergeFinalProof = (
    await Merger.merge(
      dynFirstMerge,
      VKS.merger,
      dynSignedAttrs,
      VKS.signedAttrs,
    )
  ).proof;
}

await main();
