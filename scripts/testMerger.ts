import {
  DynamicProof,
  FeatureFlags,
  Field,
  Poseidon,
  Proof,
  Provable,
  SelfProof,
  Struct,
  Undefined,
  VerificationKey,
  ZkProgram,
} from "o1js";

export class Out extends Struct({
  left: Field,
  right: Field,
  vkDigest: Field,
}) {}

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
    // Method for merging leaf proofs
    // mergeLeaves: {
    //   privateInputs: [
    //     LeafProofLeft,
    //     VerificationKey,
    //     LeafProofRight,
    //     VerificationKey,
    //   ],
    //   async method(
    //     proofLeft: LeafProofLeft,
    //     vkLeft: VerificationKey,
    //     proofRight: LeafProofRight,
    //     vkRight: VerificationKey,
    //   ) {
    //     proofLeft.verify(vkLeft);
    //     proofRight.verify(vkRight);

    //     const outLeft = proofLeft.publicOutput;
    //     const outRight = proofRight.publicOutput;

    //     outLeft.right.assertEquals(outRight.left);

    //     // Capture the verification keys
    //     const vkLeftDigest = vkLeft.hash;
    //     const vkRightDigest = vkRight.hash;
    //     const vkDigest = Poseidon.hash([vkLeftDigest, vkRightDigest]);

    //     return {
    //       publicOutput: new Out({
    //         left: outLeft.left,
    //         right: outRight.right,
    //         vkDigest: vkDigest,
    //       }),
    //     };
    //   },
    // },
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
        Provable.log("In mergeLeaves - beginning");

        Provable.log("About to verify left proof");
        proofLeft.verify(vkLeft);
        Provable.log("Left proof verified successfully");

        Provable.log("About to verify right proof");
        proofRight.verify(vkRight);
        Provable.log("Right proof verified successfully");

        const outLeft = proofLeft.publicOutput;
        const outRight = proofRight.publicOutput;

        Provable.log("Left output:", outLeft);
        Provable.log("Right output:", outRight);
        Provable.log("Left output right:", outLeft.right);
        Provable.log("Right output left:", outRight.left);

        Provable.log("About to assert left.right equals right.left");
        outLeft.right.assertEquals(outRight.left);
        Provable.log("Assertion successful");

        // Capture the verification keys
        Provable.log("Calculating VK digest");
        const vkLeftDigest = vkLeft.hash;
        Provable.log("Left VK digest:", vkLeftDigest);

        const vkRightDigest = vkRight.hash;
        Provable.log("Right VK digest:", vkRightDigest);

        const vkDigest = Poseidon.hash([vkLeftDigest, vkRightDigest]);
        Provable.log("Combined VK digest:", vkDigest);

        Provable.log("Creating output object");
        const output = new Out({
          left: outLeft.left,
          right: outRight.right,
          vkDigest: vkDigest,
        });
        Provable.log("Output object created");

        Provable.log("About to return");
        return {
          publicOutput: output,
        };
      },
    },

    // Method for processing a single leaf
    // processSingleLeaf: {
    //   privateInputs: [LeafProofLeft, VerificationKey],
    //   async method(proof: LeafProofLeft, vk: VerificationKey) {
    //     proof.verify(vk);

    //     const out = proof.publicOutput;

    //     // Capture the verification key
    //     const vkDigest = vk.hash;

    //     return {
    //       publicOutput: new Out({
    //         left: out.left,
    //         right: out.right,
    //         vkDigest: vkDigest,
    //       }),
    //     };
    //   },
    // },
    processSingleLeaf: {
      privateInputs: [LeafProofLeft, VerificationKey],
      async method(proof: LeafProofLeft, vk: VerificationKey) {
        Provable.log("In processSingleLeaf");
        Provable.log("Proof:", proof);
        Provable.log("VK:", vk);

        // Try to get the proof length and other properties
        Provable.log("About to verify proof");
        proof.verify(vk);
        Provable.log("Proof verified");

        const out = proof.publicOutput;
        Provable.log("Output:", out);

        // Capture the verification key
        const vkDigest = vk.hash;
        Provable.log("VK digest:", vkDigest);

        return {
          publicOutput: new Out({
            left: out.left,
            right: out.right,
            vkDigest: vkDigest,
          }),
        };
      },
    },

    // Method for merging merger proofs
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
  },
});

export class MergerProof extends ZkProgram.Proof(Merger) {}

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

function validateProofNeighborhood(
  leftProof: Proof<undefined, Out>,
  rightProof: Proof<undefined, Out>,
): boolean {
  return (
    leftProof.publicOutput.right.toString() ===
    rightProof.publicOutput.left.toString()
  );
}

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

export async function generateRootProof(
  proofs: Proof<undefined, Out>[],
  vks: VerificationKey[],
): Promise<MergerProof> {
  console.log(
    `Starting generateRootProof with ${proofs.length} proofs and ${vks.length} verification keys`,
  );

  if (proofs.length !== vks.length) {
    throw new Error("Number of proofs must match number of verification keys");
  }
  if (proofs.length === 0) throw Error("Empty array of proofs");

  // Validate neighborhood relationships before processing
  for (let i = 0; i < proofs.length - 1; i++) {
    console.log(`Validating neighborhood between proof ${i} and ${i + 1}`);
    console.log(`Proof ${i} right: ${proofs[i].publicOutput.right.toString()}`);
    console.log(
      `Proof ${i + 1} left : ${proofs[i + 1].publicOutput.left.toString()}`,
    );

    if (!validateProofNeighborhood(proofs[i], proofs[i + 1])) {
      throw new Error(`Neighborhood mismatch between proofs at indices ${i} and ${i + 1}:
          left.right (${proofs[i].publicOutput.right}) != right.left (${proofs[i + 1].publicOutput.left})`);
    }
    console.log(`Neighborhood validation passed for proofs ${i} and ${i + 1}`);
  }

  // First level: convert leaf proofs to merger proofs
  let currentLevel: MergerProof[] = [];

  // Process pairs of leaf proofs
  for (let i = 0; i < proofs.length - 1; i += 2) {
    console.log(`Processing leaf pair ${i} and ${i + 1}`);

    try {
      // Create left/right dynamic proofs
      console.log(`Converting proof ${i} to LeafProofLeft`);
      const proofLeft = LeafProofLeft.fromProof(proofs[i]);

      console.log(`Converting proof ${i + 1} to LeafProofRight`);
      const proofRight = LeafProofRight.fromProof(proofs[i + 1]);

      const vkLeft = vks[i];
      const vkRight = vks[i + 1];

      console.log(`Merging leaves ${i} and ${i + 1}`);
      const mergeResult = await Merger.mergeLeaves(
        proofLeft,
        vkLeft,
        proofRight,
        vkRight,
      );
      console.log(`Successfully merged leaves ${i} and ${i + 1}`);

      currentLevel.push(mergeResult.proof);
    } catch (error) {
      console.error(`Error processing leaf pair ${i} and ${i + 1}:`, error);
      throw error;
    }
  }

  // Handle odd element if present
  if (proofs.length % 2 === 1) {
    const lastIdx = proofs.length - 1;
    console.log(`Processing single leaf ${lastIdx}`);

    try {
      const lastProof = LeafProofLeft.fromProof(proofs[lastIdx]);
      const lastVk = vks[lastIdx];

      console.log(`Creating single leaf merger proof for leaf ${lastIdx}`);
      const singleResult = await Merger.processSingleLeaf(lastProof, lastVk);
      console.log(`Successfully processed single leaf ${lastIdx}`);

      currentLevel.push(singleResult.proof);
    } catch (error) {
      console.error(`Error processing single leaf ${lastIdx}:`, error);
      throw error;
    }
  }

  console.log(
    `First level of merger proofs created: ${currentLevel.length} proofs`,
  );

  // Merge until we have a single root proof
  let level = 1;
  while (currentLevel.length > 1) {
    level++;
    console.log(
      `Starting merger level ${level} with ${currentLevel.length} proofs`,
    );
    const nextLevel: MergerProof[] = [];

    // Process pairs of merger proofs
    for (let i = 0; i < currentLevel.length - 1; i += 2) {
      console.log(`Merging merger proofs ${i} and ${i + 1} at level ${level}`);

      try {
        const mergeResult = await Merger.mergeMergers(
          currentLevel[i],
          currentLevel[i + 1],
        );
        console.log(
          `Successfully merged merger proofs ${i} and ${i + 1} at level ${level}`,
        );

        nextLevel.push(mergeResult.proof);
      } catch (error) {
        console.error(
          `Error merging merger proofs ${i} and ${i + 1} at level ${level}:`,
          error,
        );
        throw error;
      }
    }

    // Handle odd element if present
    if (currentLevel.length % 2 === 1) {
      console.log(`Passing through odd merger proof at level ${level}`);
      // Pass the last proof as is to the next level
      nextLevel.push(currentLevel[currentLevel.length - 1]);
    }

    currentLevel = nextLevel;
    console.log(
      `Completed merger level ${level}, now have ${currentLevel.length} proofs`,
    );
  }

  console.log(`Root proof generation complete`);
  return currentLevel[0];
}

// Four leaf programs, each producing a value in sequence
const Leaf1 = ZkProgram({
  name: "leaf-1",
  publicOutput: Out,
  methods: {
    generate: {
      privateInputs: [],
      async method() {
        return {
          publicOutput: new Out({
            left: Field(1),
            right: Field(2),
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});

const Leaf2 = ZkProgram({
  name: "leaf-2",
  publicOutput: Out,
  methods: {
    generate: {
      privateInputs: [],
      async method() {
        return {
          publicOutput: new Out({
            left: Field(2),
            right: Field(3),
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});

const Leaf3 = ZkProgram({
  name: "leaf-3",
  publicOutput: Out,
  methods: {
    generate: {
      privateInputs: [],
      async method() {
        return {
          publicOutput: new Out({
            left: Field(3),
            right: Field(4),
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});

const Leaf4 = ZkProgram({
  name: "leaf-4",
  publicOutput: Out,
  methods: {
    generate: {
      privateInputs: [],
      async method() {
        return {
          publicOutput: new Out({
            left: Field(4),
            right: Field(5),
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});

async function main() {
  console.log("Compiling all programs...");

  // Compile leaf programs
  const { verificationKey: vkLeaf1 } = await Leaf1.compile();
  const { verificationKey: vkLeaf2 } = await Leaf2.compile();
  const { verificationKey: vkLeaf3 } = await Leaf3.compile();
  const { verificationKey: vkLeaf4 } = await Leaf4.compile();

  // Compile merger
  const { verificationKey: vkMerger } = await Merger.compile();

  console.log("Generating leaf proofs...");

  // Generate all leaf proofs
  const leaf1Result = await Leaf1.generate();
  const leaf2Result = await Leaf2.generate();
  const leaf3Result = await Leaf3.generate();
  const leaf4Result = await Leaf4.generate();

  console.log("Converting to dynamic proofs...");

  // Wrap all leaf proofs
  const dynLeaf1 = LeafProofLeft.fromProof(leaf1Result.proof);
  const dynLeaf2 = LeafProofRight.fromProof(leaf2Result.proof);
  const dynLeaf3 = LeafProofLeft.fromProof(leaf3Result.proof);
  const dynLeaf4 = LeafProofRight.fromProof(leaf4Result.proof);

  console.log("Building first level merges...");

  // First level merges (leaves -> level 1 nodes)
  const merge1Result = await Merger.mergeLeaves(
    dynLeaf1,
    vkLeaf1,
    dynLeaf2,
    vkLeaf2,
  );
  const merge2Result = await Merger.mergeLeaves(
    dynLeaf3,
    vkLeaf3,
    dynLeaf4,
    vkLeaf4,
  );

  console.log("Level 1 results:");
  console.log("Left merger:", JSON.stringify(merge1Result.proof.publicOutput));
  console.log("Right merger:", JSON.stringify(merge2Result.proof.publicOutput));

  console.log("Building root merge...");

  // Final merge (level 1 nodes -> root)
  const rootResult = await Merger.mergeMergers(
    merge1Result.proof,
    merge2Result.proof,
  );

  console.log("Root result:", JSON.stringify(rootResult.proof.publicOutput));

  // Validate the final result
  const expectedLeft = Field(1);
  const expectedRight = Field(5);

  const vkLeft = Poseidon.hash([vkLeaf1.hash, vkLeaf2.hash]);
  const vkRight = Poseidon.hash([vkLeaf3.hash, vkLeaf4.hash]);
  const vkRoot = Poseidon.hash([vkLeft, vkRight]);

  console.log("Validation:");
  console.log("Expected left:", expectedLeft.toString());
  console.log("Actual left:", rootResult.proof.publicOutput.left.toString());
  console.log("Expected right:", expectedRight.toString());
  console.log("Actual right:", rootResult.proof.publicOutput.right.toString());
  console.log("Expected root:", vkRoot.toString());
  console.log(
    "Actual root:",
    rootResult.proof.publicOutput.vkDigest.toString(),
  );

  if (
    rootResult.proof.publicOutput.left.equals(expectedLeft).toBoolean() &&
    rootResult.proof.publicOutput.right.equals(expectedRight).toBoolean() &&
    rootResult.proof.publicOutput.vkDigest.equals(vkRoot).toBoolean()
  ) {
    console.log("✅ Test passed: Complete tree correctly built from 4 leaves!");

    // Verify the connections in our binary tree
    // Tree structure:    Root
    //                   /    \
    //                 M1      M2
    //                / \     / \
    //               L1  L2  L3  L4
    console.log("\nVerifying complete tree structure:");
    console.log("Leaf1 output: 1→2");
    console.log("Leaf2 output: 2→3");
    console.log("Left merger (M1) correctly connects Leaf1 and Leaf2: 1→3");
    console.log("Leaf3 output: 3→4");
    console.log("Leaf4 output: 4→5");
    console.log("Right merger (M2) correctly connects Leaf3 and Leaf4: 3→5");
    console.log("Root merger correctly connects M1 and M2: 1→5");
    console.log("\nComplete binary tree successfully built and verified! 🌲");
  } else {
    console.error("❌ Test failed: Final output doesn't match expected values");
  }
}

await main();
