import {
  DynamicProof,
  FeatureFlags,
  Field,
  Poseidon,
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
