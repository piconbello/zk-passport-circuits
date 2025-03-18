import fs from "node:fs";
import path from "node:path";
import { Bytes, Field, Poseidon, VerificationKey, ZkProgram } from "o1js";
import { DynamicSHA2 } from "@egemengol/mina-credentials";
import { sha256 } from "@noble/hashes/sha256";
import { secp256r1 } from "@noble/curves/p256";

import { parseBundle } from "../src/parseBundle.ts";
import { ProofCache } from "../src/proofCache";
import { time } from "../src/timer.ts";
import {
  Bytes32,
  Bytes65,
  DG1_TD3,
  LDS_256_Step,
  LDS_256_LastStep,
  LDS_256_Verifier,
  LDS_256,
  SIGNED_ATTRS_256,
  DG1_TD3_256,
  LDS_DIGEST_BLOCKS_PER_ITERATION_256,
  LdsDigestState_256,
  SignedAttrs_256,
  Field3,
  VerifySignedAttrs_size256_sha256,
  VerifySignedAttrs_size256_sha256_Input,
  EcdsaSecp256r1,
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
        return (await DG1_TD3_256.compile()).verificationKey;
      });
      const proof = await time("Proving dg1", async () => {
        return (await DG1_TD3_256.td3_256(DG1_TD3.from(bundle.dg1))).proof;
      });
      return {
        proofJSON: JSON.stringify(proof.toJSON()),
        verificationKeyJSON: vkToJSON(vk),
      };
    },
  );

  const pDG1 = await ZkProgram.Proof(DG1_TD3_256).fromJSON(
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
        return (await LDS_256_Step.compile()).verificationKey;
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
        return (await LDS_256_LastStep.compile()).verificationKey;
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
    LDS_DIGEST_BLOCKS_PER_ITERATION_256,
    LDS_256.fromBytes(bundle.lds),
  );

  let curState = new LdsDigestState_256(LdsDigestState_256.initial());

  // Process each LDS step
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    const stepResult = await cache.getProof(
      path.resolve(__dirname, "../unrolled_leaves/lds_256.ts"),
      `lds_step_${i}_${bundle.dg1}`,
      async () => {
        const proof = await time(`Proving lds step ${i}`, async () => {
          return (await LDS_256_Step.step_256(carry, curState, step)).proof;
        });
        return {
          proofJSON: JSON.stringify(proof.toJSON()),
          verificationKeyJSON: vkToJSON(vkLDS_step), // Reuse the VK we already have
        };
      },
    );

    const stepProof = await ZkProgram.Proof(LDS_256_Step).fromJSON(
      JSON.parse(stepResult.proofJSON),
    );
    proofsLDS_step.push(stepProof);
    curState = new LdsDigestState_256(DynamicSHA2.update(curState, step));
  }

  // Process last step
  const lastStepResult = await cache.getProof(
    path.resolve(__dirname, "../unrolled_leaves/lds_256.ts"),
    `lds_laststep_${bundle.dg1}`,
    async () => {
      const proof = await time("Proving lds laststep", async () => {
        return (await LDS_256_LastStep.laststep_256(carry, curState, laststep))
          .proof;
      });
      return {
        proofJSON: JSON.stringify(proof.toJSON()),
        verificationKeyJSON: vkToJSON(vkLDS_laststep), // Reuse the VK we already have
      };
    },
  );

  const pLDS_laststep = await ZkProgram.Proof(LDS_256_LastStep).fromJSON(
    JSON.parse(lastStepResult.proofJSON),
  );
  curState = new LdsDigestState_256(
    DynamicSHA2.finalizeOnly(curState, laststep),
  );

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
        return (await LDS_256_Verifier.compile()).verificationKey;
      });

      const proof = await time("Verifying LDS", async () => {
        return (
          await LDS_256_Verifier.verifyLDS(
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

  const pLDS = await ZkProgram.Proof(LDS_256_Verifier).fromJSON(
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
        return (await SignedAttrs_256.compile()).verificationKey;
      });

      const proof = await time("Proving signed attrs", async () => {
        return (
          await SignedAttrs_256._256(
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

  const pSignedAttrs = await ZkProgram.Proof(SignedAttrs_256).fromJSON(
    JSON.parse(signedAttrsResult.proofJSON),
  );
  const vkSignedAttrs = vkFromJSON(signedAttrsResult.verificationKeyJSON);

  // Verify SignedAttrs with signature
  // We need to extract the public key and signature from the bundle
  const verifySignedAttrsResult = await cache.getProof(
    path.resolve(
      __dirname,
      "../unrolled_leaves/verify_signedAttrs_size256_sha256.ts",
    ),
    {
      signedAttrs: Array.from(bundle.signed_attrs),
      signature_r: bundle.document_signature.r.toString(),
      signature_s: bundle.document_signature.s.toString(),
      pubkey_x: bundle.cert_local_pubkey.x.toString(),
      pubkey_y: bundle.cert_local_pubkey.y.toString(),
    },
    async () => {
      const vk = await time("Compiling verify signed attrs", async () => {
        return (await VerifySignedAttrs_size256_sha256.compile())
          .verificationKey;
      });

      const pubkeyPoint = new secp256r1.ProjectivePoint(
        bundle.cert_local_pubkey.x,
        bundle.cert_local_pubkey.y,
        1n,
      );
      const pubkeySerial = pubkeyPoint.toRawBytes(false);

      // Convert signature r and s bigints into Field3s
      const signature = new EcdsaSecp256r1({
        r: bundle.document_signature.r,
        s: bundle.document_signature.s,
      });
      const signature_r = signature.r.toFields();
      const signature_s = signature.s.toFields();
      const input = new VerifySignedAttrs_size256_sha256_Input({
        signedAttrs: SIGNED_ATTRS_256.from(bundle.signed_attrs),
        pubkeySerial: Bytes65.from(pubkeySerial),
        signature_r: Field3.from(signature_r),
        signature_s: Field3.from(signature_s),
      });

      const proof = await time("Proving verify signed attrs", async () => {
        return (await VerifySignedAttrs_size256_sha256.verifySign(input)).proof;
      });

      return {
        proofJSON: JSON.stringify(proof.toJSON()),
        verificationKeyJSON: vkToJSON(vk),
      };
    },
  );

  const pVerifySignedAttrs = await ZkProgram.Proof(
    VerifySignedAttrs_size256_sha256,
  ).fromJSON(JSON.parse(verifySignedAttrsResult.proofJSON));
  const vkVerifySignedAttrs = vkFromJSON(
    verifySignedAttrsResult.verificationKeyJSON,
  );

  console.log("🍃 Leaves! 🍃");

  const vks = [
    vkDG1,
    ...Array(proofsLDS_step.length).fill(vkLDS_step),
    vkLDS_laststep,
    vkLDS_verifier,
    vkSignedAttrs,
    vkVerifySignedAttrs,
  ];

  const rootProof = await generateRootProof(
    [
      pDG1,
      ...proofsLDS_step,
      pLDS_laststep,
      pLDS,
      pSignedAttrs,
      pVerifySignedAttrs,
    ],
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
