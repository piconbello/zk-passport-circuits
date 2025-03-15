import {
  DynamicProof,
  FeatureFlags,
  Field,
  Poseidon,
  SelfProof,
  Undefined,
  VerificationKey,
  ZkProgram,
  Proof,
  Provable,
} from "o1js";
import { Out } from "./out";

// For leaf program proofs
export class LeafProofLeft extends DynamicProof<Undefined, Out> {
  static publicInputType = Undefined;
  static publicOutputType = Out;
  static maxProofsVerified = 0 as const;
  static featureFlags = FeatureFlags.allMaybe;
}

export class LeafProofRight extends DynamicProof<Undefined, Out> {
  static publicInputType = Undefined;
  static publicOutputType = Out;
  static maxProofsVerified = 0 as const;
  static featureFlags = FeatureFlags.allMaybe;
}

export const Merger = ZkProgram({
  name: "merger",
  publicOutput: Out,
  methods: {
    mergeLeaves: {
      privateInputs: [
        LeafProofLeft,
        VerificationKey,
        LeafProofRight,
        VerificationKey,
      ],
      async method(
        proofLeft: LeafProofLeft,
        vkLeft: VerificationKey,
        proofRight: LeafProofRight,
        vkRight: VerificationKey,
      ) {
        proofLeft.verify(vkLeft);
        proofRight.verify(vkRight);

        const outLeft = proofLeft.publicOutput;
        const outRight = proofRight.publicOutput;

        outLeft.right.assertEquals(outRight.left);

        // Capture the verification keys
        const vkLeftDigest = vkLeft.hash;
        const vkRightDigest = vkRight.hash;
        const vkDigest = Poseidon.hash([vkLeftDigest, vkRightDigest]);

        return {
          publicOutput: new Out({
            left: outLeft.left,
            right: outRight.right,
            vkDigest: vkDigest,
          }),
        };
      },
    },

    processSingleLeaf: {
      privateInputs: [LeafProofLeft, VerificationKey],
      async method(proof: LeafProofLeft, vk: VerificationKey) {
        proof.verify(vk);

        const out = proof.publicOutput;

        // Capture the verification key
        const vkDigest = vk.hash;

        return {
          publicOutput: new Out({
            left: out.left,
            right: out.right,
            vkDigest: vkDigest,
          }),
        };
      },
    },

    mergeMergers: {
      privateInputs: [SelfProof, SelfProof],
      async method(
        proofLeft: SelfProof<Undefined, Out>,
        proofRight: SelfProof<Undefined, Out>,
      ) {
        // No need to pass verification keys - they're implicit with SelfProof
        proofLeft.verify();
        proofRight.verify();

        const outLeft = proofLeft.publicOutput;
        const outRight = proofRight.publicOutput;

        outLeft.right.assertEquals(outRight.left);

        const vkDigest = Poseidon.hash([outLeft.vkDigest, outRight.vkDigest]);

        return {
          publicOutput: new Out({
            left: outLeft.left,
            right: outRight.right,
            vkDigest,
          }),
        };
      },
    },

    obfuscate: {
      privateInputs: [SelfProof],
      async method(pObvious: SelfProof<Undefined, Out>) {
        pObvious.verify();
        return {
          publicOutput: new Out({
            left: pObvious.publicOutput.left,
            right: pObvious.publicOutput.right,
            vkDigest: Poseidon.hash([pObvious.publicOutput.vkDigest]),
          }),
        };
      },
    },
  },
});

export class MergerProof extends ZkProgram.Proof(Merger) {}

// export function calculateRootVKDigest(vks: VerificationKey[]): Field {
//   if (vks.length === 0) throw Error("Empty array of VerificationKeys");
//   if (vks.length === 1) return vks[0].hash;

//   // Initial transformation of VKs to their hashes
//   let currentLevel = vks.map((vk) => vk.hash);

//   // Keep reducing until we have a single value
//   while (currentLevel.length > 1) {
//     const nextLevel: Field[] = [];

//     // Process pairs
//     for (let i = 0; i < currentLevel.length - 1; i += 2) {
//       nextLevel.push(Poseidon.hash([currentLevel[i], currentLevel[i + 1]]));
//     }

//     // Handle odd element if present
//     if (currentLevel.length % 2 === 1) {
//       nextLevel.push(currentLevel[currentLevel.length - 1]);
//     }

//     currentLevel = nextLevel;
//   }

//   return currentLevel[0];
// }

// function validateProofNeighborhood(
//   leftProof: Proof<undefined, Out>,
//   rightProof: Proof<undefined, Out>,
// ): boolean {
//   return (
//     leftProof.publicOutput.right.toString() ===
//     rightProof.publicOutput.left.toString()
//   );
// }

// export async function generateRootProof(
//   proofs: Proof<undefined, Out>[],
//   vks: VerificationKey[],
// ): Promise<MergerProof> {
//   if (proofs.length !== vks.length) {
//     throw new Error("Number of proofs must match number of verification keys");
//   }
//   if (proofs.length === 0) throw Error("Empty array of proofs");

//   // Validate neighborhood relationships before processing
//   for (let i = 0; i < proofs.length - 1; i++) {
//     if (!validateProofNeighborhood(proofs[i], proofs[i + 1])) {
//       throw new Error(`Neighborhood mismatch between proofs at indices ${i} and ${i + 1}:
//           left.right (${proofs[i].publicOutput.right}) != right.left (${proofs[i + 1].publicOutput.left})`);
//     }
//   }

//   // First level: convert leaf proofs to merger proofs
//   let currentLevel: MergerProof[] = [];

//   // Process pairs of leaf proofs
//   for (let i = 0; i < proofs.length - 1; i += 2) {
//     // Create left/right dynamic proofs
//     const proofLeft = LeafProofLeft.fromProof(proofs[i]);
//     // Use LeafProofRight for even indices
//     const proofRight = LeafProofRight.fromProof(proofs[i + 1]);

//     const vkLeft = vks[i];
//     const vkRight = vks[i + 1];

//     const mergeResult = await Merger.mergeLeaves(
//       proofLeft,
//       vkLeft,
//       proofRight,
//       vkRight,
//     );

//     currentLevel.push(mergeResult.proof);
//   }

//   // Handle odd element if present
//   if (proofs.length % 2 === 1) {
//     const lastIdx = proofs.length - 1;
//     const lastProof = LeafProofLeft.fromProof(proofs[lastIdx]);
//     const lastVk = vks[lastIdx];

//     const singleResult = await Merger.processSingleLeaf(lastProof, lastVk);
//     currentLevel.push(singleResult.proof);
//   }

//   // Merge until we have a single root proof
//   while (currentLevel.length > 1) {
//     const nextLevel: MergerProof[] = [];

//     // Process pairs of merger proofs
//     for (let i = 0; i < currentLevel.length - 1; i += 2) {
//       const mergeResult = await Merger.mergeMergers(
//         currentLevel[i],
//         currentLevel[i + 1],
//       );

//       nextLevel.push(mergeResult.proof);
//     }

//     // Handle odd element if present
//     if (currentLevel.length % 2 === 1) {
//       // Pass the last proof as is to the next level
//       nextLevel.push(currentLevel[currentLevel.length - 1]);
//     }

//     currentLevel = nextLevel;
//   }

//   return currentLevel[0];
// }

// // export async function generateRootProof(
// //   proofs: Proof<undefined, Out>[],
// //   vks: VerificationKey[],
// // ): Promise<MergerProof> {
// //   console.log(
// //     `Starting generateRootProof with ${proofs.length} proofs and ${vks.length} verification keys`,
// //   );

// //   if (proofs.length !== vks.length) {
// //     throw new Error("Number of proofs must match number of verification keys");
// //   }
// //   if (proofs.length === 0) throw Error("Empty array of proofs");

// //   // Validate neighborhood relationships before processing
// //   for (let i = 0; i < proofs.length - 1; i++) {
// //     console.log(`Validating neighborhood between proof ${i} and ${i + 1}`);
// //     console.log(`Proof ${i} right: ${proofs[i].publicOutput.right.toString()}`);
// //     console.log(
// //       `Proof ${i + 1} left : ${proofs[i + 1].publicOutput.left.toString()}`,
// //     );

// //     if (!validateProofNeighborhood(proofs[i], proofs[i + 1])) {
// //       throw new Error(`Neighborhood mismatch between proofs at indices ${i} and ${i + 1}:
// //           left.right (${proofs[i].publicOutput.right}) != right.left (${proofs[i + 1].publicOutput.left})`);
// //     }
// //     console.log(`Neighborhood validation passed for proofs ${i} and ${i + 1}`);
// //   }

// //   // First level: convert leaf proofs to merger proofs
// //   let currentLevel: MergerProof[] = [];

// //   // Process pairs of leaf proofs
// //   for (let i = 0; i < proofs.length - 1; i += 2) {
// //     console.log(`Processing leaf pair ${i} and ${i + 1}`);

// //     try {
// //       // Create left/right dynamic proofs
// //       console.log(`Converting proof ${i} to LeafProofLeft`);
// //       const proofLeft = LeafProofLeft.fromProof(proofs[i]);

// //       console.log(`Converting proof ${i + 1} to LeafProofRight`);
// //       const proofRight = LeafProofRight.fromProof(proofs[i + 1]);

// //       const vkLeft = vks[i];
// //       const vkRight = vks[i + 1];

// //       console.log(`Merging leaves ${i} and ${i + 1}`);
// //       const mergeResult = await Merger.mergeLeaves(
// //         proofLeft,
// //         vkLeft,
// //         proofRight,
// //         vkRight,
// //       );
// //       console.log(`Successfully merged leaves ${i} and ${i + 1}`);

// //       currentLevel.push(mergeResult.proof);
// //     } catch (error) {
// //       console.error(`Error processing leaf pair ${i} and ${i + 1}:`, error);
// //       throw error;
// //     }
// //   }

// //   // Handle odd element if present
// //   if (proofs.length % 2 === 1) {
// //     const lastIdx = proofs.length - 1;
// //     console.log(`Processing single leaf ${lastIdx}`);

// //     try {
// //       const lastProof = LeafProofLeft.fromProof(proofs[lastIdx]);
// //       const lastVk = vks[lastIdx];

// //       console.log(`Creating single leaf merger proof for leaf ${lastIdx}`);
// //       const singleResult = await Merger.processSingleLeaf(lastProof, lastVk);
// //       console.log(`Successfully processed single leaf ${lastIdx}`);

// //       currentLevel.push(singleResult.proof);
// //     } catch (error) {
// //       console.error(`Error processing single leaf ${lastIdx}:`, error);
// //       throw error;
// //     }
// //   }

// //   console.log(
// //     `First level of merger proofs created: ${currentLevel.length} proofs`,
// //   );

// //   // Merge until we have a single root proof
// //   let level = 1;
// //   while (currentLevel.length > 1) {
// //     level++;
// //     console.log(
// //       `Starting merger level ${level} with ${currentLevel.length} proofs`,
// //     );
// //     const nextLevel: MergerProof[] = [];

// //     // Process pairs of merger proofs
// //     for (let i = 0; i < currentLevel.length - 1; i += 2) {
// //       console.log(`Merging merger proofs ${i} and ${i + 1} at level ${level}`);

// //       try {
// //         const mergeResult = await Merger.mergeMergers(
// //           currentLevel[i],
// //           currentLevel[i + 1],
// //         );
// //         console.log(
// //           `Successfully merged merger proofs ${i} and ${i + 1} at level ${level}`,
// //         );

// //         nextLevel.push(mergeResult.proof);
// //       } catch (error) {
// //         console.error(
// //           `Error merging merger proofs ${i} and ${i + 1} at level ${level}:`,
// //           error,
// //         );
// //         throw error;
// //       }
// //     }

// //     // Handle odd element if present
// //     if (currentLevel.length % 2 === 1) {
// //       console.log(`Passing through odd merger proof at level ${level}`);
// //       // Pass the last proof as is to the next level
// //       nextLevel.push(currentLevel[currentLevel.length - 1]);
// //     }

// //     currentLevel = nextLevel;
// //     console.log(
// //       `Completed merger level ${level}, now have ${currentLevel.length} proofs`,
// //     );
// //   }

// //   console.log(`Root proof generation complete`);
// //   return currentLevel[0];
// // }
