import { Field, type JsonProof, Poseidon, Proof, VerificationKey } from "o1js";
import type { Out } from "../../unrolled_meta/out";

import * as fs from "node:fs";
import * as path from "node:path";
import {
  LeafProofLeft,
  LeafProofRight,
  Merger,
  MergerProof,
} from "../../unrolled_meta/merger";
import { log } from "../../unrolled_meta/logger";
import { deserializeRichProof, type RichProof } from "./richProof";

function validateProofNeighborhood(
  leftProof: MergerProof,
  rightProof: MergerProof,
): boolean {
  return (
    leftProof.publicOutput.right.toString() ===
    rightProof.publicOutput.left.toString()
  );
}

export async function mergeUntilSingle(
  logger: typeof log,
  richProofs: RichProof[],
) {
  // Validate neighborhood relationships before processing

  for (let i = 0; i < richProofs.length - 1; i++) {
    const left = richProofs[i].proof;
    const right = richProofs[i + 1].proof;
    if (!validateProofNeighborhood(left, right)) {
      throw new Error(`Neighborhood mismatch between proofs at indices ${i} and ${i + 1}:
          left.right (${left.publicOutput.right}) != right.left (${right.publicOutput.left})`);
    }
  }

  logger.start("compiling Merger");
  const vk = (await Merger.compile()).verificationKey;
  logger.finish("compiling Merger");

  // LEAVES
  let currentLevel: MergerProof[] = [];
  for (let i = 0; i < richProofs.length - 1; i += 2) {
    const proofLeft = LeafProofLeft.fromProof(richProofs[i].proof);
    const proofRight = LeafProofRight.fromProof(richProofs[i + 1].proof);

    const vkLeft = richProofs[i].vk;
    const vkRight = richProofs[i + 1].vk;

    logger.start(`merging leaf pair at ${i}`);
    const mergeResult = await Merger.mergeLeaves(
      proofLeft,
      vkLeft,
      proofRight,
      vkRight,
    );
    logger.finish(`merging leaf pair at ${i}`);
    currentLevel.push(mergeResult.proof);
  }

  // Handle odd element if present
  if (richProofs.length % 2 === 1) {
    const lastProof = LeafProofLeft.fromProof(
      richProofs[richProofs.length - 1].proof,
    );
    const lastVk = richProofs[richProofs.length - 1].vk;

    logger.start(`processing last leaf`);
    const singleResult = await Merger.processSingleLeaf(lastProof, lastVk);
    logger.finish(`processing last leaf`);
    currentLevel.push(singleResult.proof);
  }

  let level = 1;
  while (currentLevel.length > 1) {
    level++;
    const nextLevel: MergerProof[] = [];
    // Process pairs of merger proofs
    for (let i = 0; i < currentLevel.length - 1; i += 2) {
      const leftOutput = currentLevel[i].publicOutput;
      const rightOutput = currentLevel[i + 1].publicOutput;

      logger.start(`merging middle node pairs`);
      const result = await Merger.mergeMergers(
        currentLevel[i],
        currentLevel[i + 1],
      );
      logger.finish(`merging middle node pairs`);
      nextLevel.push(result.proof);
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

async function mergeLeaves(logger: typeof log, leafProofJsonPaths: string[]) {
  const richProofs = [];
  for (const f of leafProofJsonPaths) {
    const richProof = await deserializeRichProof(
      fs.readFileSync(f, { encoding: "utf-8" }),
    );
    richProofs.push(richProof);
  }
  const rootProof = await mergeUntilSingle(logger, richProofs);
  return rootProof;
}

// async function main() {
//   const folder = "./files/worker";
//   const files = fs
//     .readdirSync(folder)
//     .filter((f) => f.endsWith(".json"))
//     .toSorted();
//   console.log("files", files);
//   const rootProof = await mergeLeaves(
//     log,
//     files.map((f) => path.join(folder, f)),
//   );
//   // const richProofs = [];
//   // for (const f of files) {
//   //   const richProof = await deserializeRichProof(
//   //     fs.readFileSync(path.join(folder, f), { encoding: "utf-8" }),
//   //   );
//   //   richProofs.push(richProof);
//   // }
//   // const rootProof = await mergeUntilSingle(richProofs);
//   console.log("root vk", rootProof.publicOutput.vkDigest.toBigInt());
//   // console.log("richproofs", richProofs);
// }
// if (import.meta.path === Bun.main) {
//   await main();
// }

process.on(
  "message",
  async ({
    leafProofJsonPaths,
    rootProofJsonPath,
  }: {
    leafProofJsonPaths: string[];
    rootProofJsonPath: string;
  }) => {
    const logger = log.scope("merger");
    try {
      const rootProof = await mergeLeaves(logger, leafProofJsonPaths);

      await Bun.file(rootProofJsonPath).write(
        JSON.stringify(rootProof.toJSON()),
      );
      if (process.send) {
        process.send("done");
      }
      process.exit(0); // Explicitly exit the process
    } catch (error) {
      logger.error("Error in merger worker:", error);
      process.exit(1);
    }
  },
);
