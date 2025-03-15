import fs from "node:fs";
import path from "node:path";
import {
  Bytes,
  Field,
  Poseidon,
  Proof,
  VerificationKey,
  ZkProgram,
} from "o1js";
import { DynamicSHA2 } from "@egemengol/mina-credentials";
import { sha256 } from "@noble/hashes/sha256";

import { parseBundle } from "../src/parseBundle.ts";
import { ProofCache } from "../src/proofCache";
import { time } from "../src/timer.ts";
import {
  Bytes32,
  DG1_TD3,
  DigestDG1,
  DigestLDS_laststep,
  DigestLDS_step,
  DigestLDS_verifier,
  DigestSignedAttrs,
  LDS_256,
  LDS_DIGEST_BLOCKS_PER_ITERATION,
  LdsDigestState,
  SIGNED_ATTRS_256,
} from "../unrolled_leaves";
import { Merger } from "../unrolled_meta/merger.ts";
import {
  calculateRootVKDigest,
  generateRootProof,
} from "../unrolled_meta/merger_utils.ts";

// Helper function to convert VerificationKey to JSON string
function vkToJSON(vk: VerificationKey): string {
  return JSON.stringify({
    hash: vk.hash.toJSON(),
    data: vk.data,
  });
}

// Helper function to convert JSON string to VerificationKey
function vkFromJSON(json: string): VerificationKey {
  const parsed = JSON.parse(json);
  return {
    hash: Field.fromJSON(parsed.hash),
    data: parsed.data,
  };
}

async function main() {
  const cache = new ProofCache();

  const file = fs.readFileSync("files/bundle.frodo.256-256-r1.json", "utf-8");
  const bundle = parseBundle(file);

  // Process DG1
  const dg1Result = await cache.getProof(
    path.resolve(__dirname, "../unrolled_leaves/dg1_td3_256.ts"),
    bundle.dg1,
    async () => {
      const vk = await time("Compiling dg1", async () => {
        return (await DigestDG1.compile()).verificationKey;
      });
      const proof = await time("Proving dg1", async () => {
        return (await DigestDG1.td3_256(DG1_TD3.from(bundle.dg1))).proof;
      });
      return {
        proofJSON: JSON.stringify(proof.toJSON()),
        verificationKeyJSON: vkToJSON(vk),
      };
    },
  );

  const pDG1 = await ZkProgram.Proof(DigestDG1).fromJSON(
    JSON.parse(dg1Result.proofJSON),
  );
  const vkDG1 = vkFromJSON(dg1Result.verificationKeyJSON);

  // Will carry this until the lds verifier method
  const carry: Field = Poseidon.hash(
    Bytes.from(sha256(bundle.dg1)).bytes.map((b) => b.value),
  );

  // Process LDS step
  const ldsStepVKResult = await cache.getProof(
    path.resolve(__dirname, "../unrolled_leaves/lds_256.ts"),
    "LDS_step_vk",
    async () => {
      const vk = await time("Compiling lds step", async () => {
        return (await DigestLDS_step.compile()).verificationKey;
      });
      return {
        proofJSON: "{}", // Just a placeholder, we only need the VK
        verificationKeyJSON: vkToJSON(vk),
      };
    },
  );
  const vkLDS_step = vkFromJSON(ldsStepVKResult.verificationKeyJSON);

  // Process LDS last step
  const ldsLastStepVKResult = await cache.getProof(
    path.resolve(__dirname, "../unrolled_leaves/lds_256.ts"),
    "LDS_laststep_vk",
    async () => {
      const vk = await time("Compiling lds laststep", async () => {
        return (await DigestLDS_laststep.compile()).verificationKey;
      });
      return {
        proofJSON: "{}", // Just a placeholder, we only need the VK
        verificationKeyJSON: vkToJSON(vk),
      };
    },
  );
  const vkLDS_laststep = vkFromJSON(ldsLastStepVKResult.verificationKeyJSON);

  // TODO fill nof steps with dummy if LDS is short. We know it is long for frodo.
  const proofsLDS_step = [];
  const { iterations: steps, final: laststep } = DynamicSHA2.split(
    256,
    LDS_DIGEST_BLOCKS_PER_ITERATION,
    LDS_256.fromBytes(bundle.lds),
  );

  let curState = new LdsDigestState(LdsDigestState.initial());

  // Process each LDS step
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const stepResult = await cache.getProof(
      path.resolve(__dirname, "../unrolled_leaves/lds_256.ts"),
      `lds_step_${i}_${bundle.dg1}`,
      async () => {
        const proof = await time(`Proving lds step ${i}`, async () => {
          return (await DigestLDS_step.step_256(carry, curState, step)).proof;
        });
        return {
          proofJSON: JSON.stringify(proof.toJSON()),
          verificationKeyJSON: vkToJSON(vkLDS_step), // Reuse the VK we already have
        };
      },
    );

    const stepProof = await ZkProgram.Proof(DigestLDS_step).fromJSON(
      JSON.parse(stepResult.proofJSON),
    );
    proofsLDS_step.push(stepProof);
    curState = new LdsDigestState(DynamicSHA2.update(curState, step));
  }

  // Process last step
  const lastStepResult = await cache.getProof(
    path.resolve(__dirname, "../unrolled_leaves/lds_256.ts"),
    `lds_laststep_${bundle.dg1}`,
    async () => {
      const proof = await time("Proving lds laststep", async () => {
        return (
          await DigestLDS_laststep.laststep_256(carry, curState, laststep)
        ).proof;
      });
      return {
        proofJSON: JSON.stringify(proof.toJSON()),
        verificationKeyJSON: vkToJSON(vkLDS_laststep), // Reuse the VK we already have
      };
    },
  );

  const pLDS_laststep = await ZkProgram.Proof(DigestLDS_laststep).fromJSON(
    JSON.parse(lastStepResult.proofJSON),
  );
  // proofsLDS_step.push(lastStepProof);
  curState = new LdsDigestState(DynamicSHA2.finalizeOnly(curState, laststep));

  // Process LDS verifier
  const ldsVerifierResult = await cache.getProof(
    path.resolve(__dirname, "../unrolled_leaves/lds_256.ts"),
    {
      verifier: true,
      carry: carry.toString(),
      state: curState.toString(),
      lds: Array.from(bundle.lds),
      dg1: Array.from(bundle.dg1),
    },
    async () => {
      const vk = await time("Compiling lds verifier", async () => {
        return (await DigestLDS_verifier.compile()).verificationKey;
      });

      const proof = await time("Verifying LDS", async () => {
        return (
          await DigestLDS_verifier.verifyLDS(
            carry,
            curState,
            LDS_256.fromBytes(bundle.lds),
            Bytes32.from(sha256(bundle.dg1)),
          )
        ).proof;
      });

      return {
        proofJSON: JSON.stringify(proof.toJSON()),
        verificationKeyJSON: vkToJSON(vk),
      };
    },
  );

  const pLDS = await ZkProgram.Proof(DigestLDS_verifier).fromJSON(
    JSON.parse(ldsVerifierResult.proofJSON),
  );
  const vkLDS_verifier = vkFromJSON(ldsVerifierResult.verificationKeyJSON);

  // Process Signed Attrs
  const signedAttrsResult = await cache.getProof(
    path.resolve(__dirname, "../unrolled_leaves/signedAttrs_256.ts"),
    {
      lds: Array.from(bundle.lds),
      signedAttrs: Array.from(bundle.signed_attrs),
    },
    async () => {
      const vk = await time("Compiling signed attrs", async () => {
        return (await DigestSignedAttrs.compile()).verificationKey;
      });

      const proof = await time("Proving signed attrs", async () => {
        return (
          await DigestSignedAttrs._256(
            Bytes32.from(sha256(bundle.lds)),
            SIGNED_ATTRS_256.from(bundle.signed_attrs),
          )
        ).proof;
      });

      return {
        proofJSON: JSON.stringify(proof.toJSON()),
        verificationKeyJSON: vkToJSON(vk),
      };
    },
  );

  const pSignedAttrs = await ZkProgram.Proof(DigestSignedAttrs).fromJSON(
    JSON.parse(signedAttrsResult.proofJSON),
  );
  const vkSignedAttrs = vkFromJSON(signedAttrsResult.verificationKeyJSON);

  console.log("Leaves got created successfully!");

  const vks = [
    vkDG1,
    ...Array(proofsLDS_step.length).fill(vkLDS_step),
    vkLDS_laststep,
    vkLDS_verifier,
    vkSignedAttrs,
  ];
  const rootProof = await generateRootProof(
    [pDG1, ...proofsLDS_step, pLDS_laststep, pLDS, pSignedAttrs],
    vks,
    cache,
  );

  const rootVkDigest = await calculateRootVKDigest(vks);

  console.log(rootVkDigest.toBigInt());
  console.log(rootProof.publicOutput.vkDigest.toBigInt());

  const obfuscationResult = await cache.getProof(
    path.resolve(__dirname, "../unrolled_meta/merger.ts"),
    {
      obfuscation: true,
      rootProof: rootProof.toJSON(),
    },
    async () => {
      const obfuscatedProof = await time("Obfuscating root proof", async () => {
        return (await Merger.obfuscate(rootProof)).proof;
      });

      return {
        proofJSON: JSON.stringify(obfuscatedProof.toJSON()),
        verificationKeyJSON: "{}", // We don't need to cache the VK here
      };
    },
  );

  const finalProof = await ZkProgram.Proof(Merger).fromJSON(
    JSON.parse(obfuscationResult.proofJSON),
  );

  console.log(
    "Final obfuscated VK digest:",
    finalProof.publicOutput.vkDigest.toBigInt(),
  );
  console.log("Complete pipeline executed successfully!");
}

await main();
