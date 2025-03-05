import {
  DynamicProof,
  FeatureFlags,
  Field,
  Poseidon,
  Proof,
  SelfProof,
  Struct,
  Undefined,
  VerificationKey,
  ZkProgram,
} from "o1js";
import {
  LeafProofLeft,
  LeafProofRight,
  Merger,
  MergerProof,
} from "../circuits/bimodal/merger";
import type { Out } from "../circuits/bimodal/common";

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

export async function compile(): Promise<VerificationKey> {
  return (await Merger.compile()).verificationKey;
}

function validateProofNeighborhood(
  leftProof: Proof<undefined, Out>,
  rightProof: Proof<undefined, Out>,
): boolean {
  return (
    leftProof.publicOutput.right.toString() ===
    rightProof.publicOutput.left.toString()
  );
}

export async function generateRootProof(
  proofs: Proof<undefined, Out>[],
  vks: VerificationKey[],
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
    // Create left/right dynamic proofs
    const proofLeft = LeafProofLeft.fromProof(proofs[i]);
    // Use LeafProofRight for even indices
    const proofRight = LeafProofRight.fromProof(proofs[i + 1]);

    const vkLeft = vks[i];
    const vkRight = vks[i + 1];

    const mergeResult = await Merger.mergeLeaves(
      proofLeft,
      vkLeft,
      proofRight,
      vkRight,
    );

    currentLevel.push(mergeResult.proof);
  }

  // Handle odd element if present
  if (proofs.length % 2 === 1) {
    const lastIdx = proofs.length - 1;
    const lastProof = LeafProofLeft.fromProof(proofs[lastIdx]);
    const lastVk = vks[lastIdx];

    const singleResult = await Merger.processSingleLeaf(lastProof, lastVk);
    currentLevel.push(singleResult.proof);
  }

  // Merge until we have a single root proof
  while (currentLevel.length > 1) {
    const nextLevel: MergerProof[] = [];

    // Process pairs of merger proofs
    for (let i = 0; i < currentLevel.length - 1; i += 2) {
      const mergeResult = await Merger.mergeMergers(
        currentLevel[i],
        currentLevel[i + 1],
      );

      nextLevel.push(mergeResult.proof);
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
