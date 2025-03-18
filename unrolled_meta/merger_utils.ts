import path from "node:path";
import crypto from "crypto";
import { Field, VerificationKey, ZkProgram, Proof, Poseidon } from "o1js";
import { LeafProofLeft, LeafProofRight, Merger, MergerProof } from "./merger";
import { Out } from "./out";
import { time } from "../src/timer.ts";
import { ProofCache } from "../src/proofCache.ts";
import { sha256 } from "@noble/hashes/sha256";
import { once } from "./utils.ts";

// Helper function to convert VerificationKey to JSON string
export function vkToJSON(vk: VerificationKey): string {
  return JSON.stringify({
    hash: vk.hash.toJSON(),
    data: vk.data,
  });
}

// Helper function to convert JSON string to VerificationKey
export function vkFromJSON(json: string): VerificationKey {
  const parsed = JSON.parse(json);
  return {
    hash: Field.fromJSON(parsed.hash),
    data: parsed.data,
  };
}

const compileMerger = once(async () => {
  return await time("Compiling merger program", async () => {
    return await Merger.compile();
  });
});

// Create a shortened hash for cache keys
function createDigestKey(left: Out, right: Out) {
  return sha256(
    left.left.toString() +
      left.right.toString() +
      left.vkDigest.toString() +
      right.left.toString() +
      right.right.toString() +
      right.vkDigest.toString(),
  ).slice(0, 16);
}

function createDigestKeySingle(out: Out) {
  return sha256(
    out.left.toString() + out.right.toString() + out.vkDigest.toString(),
  ).slice(0, 16);
}

// Validate that proofs can be properly chained
function validateProofNeighborhood(
  leftProof: Proof<undefined, Out>,
  rightProof: Proof<undefined, Out>,
): boolean {
  return (
    leftProof.publicOutput.right.toString() ===
    rightProof.publicOutput.left.toString()
  );
}

/**
 * Generates a root proof by merging an array of proofs recursively
 * Uses caching to avoid regenerating proofs and timing to track performance
 *
 * @param proofs Array of proofs to merge
 * @param vks Corresponding verification keys for each proof
 * @param cache The ProofCache instance to use
 * @returns A single root proof that verifies all input proofs
 */
export async function generateRootProof(
  proofs: Proof<undefined, Out>[],
  vks: VerificationKey[],
  cache: ProofCache,
): Promise<MergerProof> {
  if (proofs.length !== vks.length) {
    throw new Error("Number of proofs must match number of verification keys");
  }
  if (proofs.length === 0) throw Error("Empty array of proofs");

  // Validate neighborhood relationships before processing
  for (let i = 0; i < proofs.length - 1; i++) {
    if (!validateProofNeighborhood(proofs[i], proofs[i + 1])) {
      throw new Error(`Neighborhood mismatch between proofs at indices ${i} and ${i + 1}:
          left.right (${proofs[i].publicOutput.right}) != right.left (${proofs[i + 1].publicOutput.left})`);
    }
  }

  // First level: convert leaf proofs to merger proofs
  let currentLevel: MergerProof[] = [];

  // Process pairs of leaf proofs
  for (let i = 0; i < proofs.length - 1; i += 2) {
    const leftOutput = proofs[i].publicOutput;
    const rightOutput = proofs[i + 1].publicOutput;

    const cacheKey = createDigestKey(leftOutput, rightOutput);

    const result = await cache.getProof(
      path.resolve(__dirname, "./merger.ts"),
      cacheKey,
      async () => {
        await compileMerger();
        return await time(`Merging leaves ${i} and ${i + 1}`, async () => {
          // Create left/right dynamic proofs
          const proofLeft = LeafProofLeft.fromProof(proofs[i]);
          const proofRight = LeafProofRight.fromProof(proofs[i + 1]);

          const vkLeft = vks[i];
          const vkRight = vks[i + 1];

          const mergeResult = await Merger.mergeLeaves(
            proofLeft,
            vkLeft,
            proofRight,
            vkRight,
          );

          return {
            proofJSON: JSON.stringify(mergeResult.proof.toJSON()),
            verificationKeyJSON: vkToJSON(vks[0]), // Use the first VK as reference
          };
        });
      },
    );

    currentLevel.push(
      await ZkProgram.Proof(Merger).fromJSON(JSON.parse(result.proofJSON)),
    );
  }

  // Handle odd element if present
  if (proofs.length % 2 === 1) {
    const lastIdx = proofs.length - 1;
    const lastOutput = proofs[lastIdx].publicOutput;

    const cacheKey = createDigestKeySingle(lastOutput);

    const result = await cache.getProof(
      path.resolve(__dirname, "./merger.ts"),
      cacheKey,
      async () => {
        await compileMerger();
        return await time(`Processing single leaf ${lastIdx}`, async () => {
          const lastProof = LeafProofLeft.fromProof(proofs[lastIdx]);
          const lastVk = vks[lastIdx];

          const singleResult = await Merger.processSingleLeaf(
            lastProof,
            lastVk,
          );

          return {
            proofJSON: JSON.stringify(singleResult.proof.toJSON()),
            verificationKeyJSON: vkToJSON(vks[0]), // Use the first VK as reference
          };
        });
      },
    );

    currentLevel.push(
      await ZkProgram.Proof(Merger).fromJSON(JSON.parse(result.proofJSON)),
    );
  }

  // Merge until we have a single root proof
  let level = 1;
  while (currentLevel.length > 1) {
    level++;
    const nextLevel: MergerProof[] = [];

    // Process pairs of merger proofs
    for (let i = 0; i < currentLevel.length - 1; i += 2) {
      const leftOutput = currentLevel[i].publicOutput;
      const rightOutput = currentLevel[i + 1].publicOutput;

      const cacheKey = createDigestKey(leftOutput, rightOutput);

      const result = await cache.getProof(
        path.resolve(__dirname, "./merger.ts"),
        cacheKey,
        async () => {
          await compileMerger();
          return await time(
            `Merging proofs at level ${level}, pair ${i}`,
            async () => {
              const mergeResult = await Merger.mergeMergers(
                currentLevel[i],
                currentLevel[i + 1],
              );

              return {
                proofJSON: JSON.stringify(mergeResult.proof.toJSON()),
                verificationKeyJSON: vkToJSON(vks[0]), // Use the first VK as reference
              };
            },
          );
        },
      );

      nextLevel.push(
        await ZkProgram.Proof(Merger).fromJSON(JSON.parse(result.proofJSON)),
      );
    }

    // Handle odd element if present
    if (currentLevel.length % 2 === 1) {
      // Pass the last proof as is to the next level
      nextLevel.push(currentLevel[currentLevel.length - 1]);
    }

    currentLevel = nextLevel;
  }

  return currentLevel[0];
}

/**
 * Calculates the root verification key digest from an array of verification keys
 * by hashing them in a binary tree fashion
 *
 * @param vks Array of verification keys
 * @returns A Field representing the digest of all VKs
 */
export function calculateRootVKDigest(vks: VerificationKey[]): Field {
  if (vks.length === 0) throw Error("Empty array of VerificationKeys");
  if (vks.length === 1) return vks[0].hash;

  // Initial transformation of VKs to their hashes
  let currentLevel = vks.map((vk) => vk.hash);

  // Keep reducing until we have a single value
  while (currentLevel.length > 1) {
    const nextLevel: Field[] = [];

    // Process pairs
    for (let i = 0; i < currentLevel.length - 1; i += 2) {
      nextLevel.push(Poseidon.hash([currentLevel[i], currentLevel[i + 1]]));
    }

    // Handle odd element if present
    if (currentLevel.length % 2 === 1) {
      nextLevel.push(currentLevel[currentLevel.length - 1]);
    }

    currentLevel = nextLevel;
  }

  return currentLevel[0];
}
