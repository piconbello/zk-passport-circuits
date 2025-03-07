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
import { time } from "../src/timer";

export class Out extends Struct({
  left: Field,
  right: Field,
  vkDigest: Field,
}) {}

export class DynOutProof0 extends DynamicProof<Undefined, Out> {
  static publicInputType = Undefined;
  static publicOutputType = Out;
  static maxProofsVerified = 0 as const;
  static featureFlags = FeatureFlags.allMaybe;
}
export class DynOutProof1 extends DynamicProof<Undefined, Out> {
  static publicInputType = Undefined;
  static publicOutputType = Out;
  static maxProofsVerified = 1 as const;
  static featureFlags = FeatureFlags.allMaybe;
}

export const Merger = ZkProgram({
  name: "merger-separate",
  publicOutput: Out,
  methods: {
    acceptLeaf0: {
      privateInputs: [DynOutProof0, VerificationKey],
      async method(proof: DynOutProof0, vk: VerificationKey) {
        proof.verify(vk);
        const out = proof.publicOutput;
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
    acceptLeaf1: {
      privateInputs: [DynOutProof1, VerificationKey],
      async method(proof: DynOutProof1, vk: VerificationKey) {
        proof.verify(vk);
        const out = proof.publicOutput;
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
    merge: {
      privateInputs: [SelfProof, SelfProof],
      async method(
        proofLeft: SelfProof<Undefined, Out>,
        proofRight: SelfProof<Undefined, Out>,
      ) {
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

// Two leaf programs, one direct and one with self-verification
const Leaf1 = ZkProgram({
  name: "leaf-1-direct",
  publicOutput: Out,
  methods: {
    generate: {
      privateInputs: [],
      async method() {
        return {
          publicOutput: new Out({
            left: Field(10),
            right: Field(20),
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});

const Leaf2 = ZkProgram({
  name: "leaf-2-with-selfproof",
  publicOutput: Out,
  methods: {
    prepare: {
      privateInputs: [],
      async method() {
        return {
          publicOutput: new Out({
            left: Field(20),
            right: Field(30),
            vkDigest: Field(0),
          }),
        };
      },
    },
    generate: {
      privateInputs: [SelfProof],
      async method(prepare: SelfProof<undefined, Out>) {
        prepare.verify();
        const out = prepare.publicOutput;
        return {
          publicOutput: new Out({
            left: out.left,
            right: out.right,
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});

async function main() {
  console.log("🌱 Starting separate merger test...");

  // Compile all programs
  const { verificationKey: vkLeaf1 } = await time("Compiling Leaf1", () =>
    Leaf1.compile(),
  );
  const { verificationKey: vkLeaf2 } = await time("Compiling Leaf2", () =>
    Leaf2.compile(),
  );
  const { verificationKey: vkMerger } = await time("Compiling Merger", () =>
    Merger.compile(),
  );

  // Generate leaf proofs
  const proof1 = await time(
    "Generating Leaf1 proof",
    async () => (await Leaf1.generate()).proof,
  );

  // For Leaf2, we need the prepare step first
  const proof2intermediate = await time(
    "Generating Leaf2 prepare proof",
    async () => (await Leaf2.prepare()).proof,
  );
  const proof2 = await time(
    "Generating Leaf2 final proof",
    async () => (await Leaf2.generate(proof2intermediate)).proof,
  );

  console.log("\nLeaf proofs generated:");
  console.log("Leaf1:", proof1.publicOutput.toString());
  console.log("Leaf2:", proof2.publicOutput.toString());

  // Convert to dynamic proofs
  const dynLeaf1 = DynOutProof0.fromProof(proof1);
  const dynLeaf2 = DynOutProof1.fromProof(proof2);

  // Create merger proofs for each leaf
  const proofAccept1 = await time(
    "Creating merger proof for Leaf1",
    async () => (await Merger.acceptLeaf0(dynLeaf1, vkLeaf1)).proof,
  );
  const proofAccept2 = await time(
    "Creating merger proof for Leaf2",
    async () => (await Merger.acceptLeaf1(dynLeaf2, vkLeaf2)).proof,
  );

  console.log("\nLeaf merger proofs created:");
  console.log("Accepted1:", proofAccept1.publicOutput.toString());
  console.log("Accepted2:", proofAccept2.publicOutput.toString());

  // Final merge
  // const proofMerged = await time(
  //   "Creating final merger proof",
  //   async () => (await Merger.merge(proofAccept1, proofAccept2)).proof,
  // );

  // console.log("\n🌲 Final result:");
  // console.log(proofMerged.publicOutput.toString());

  // // Validate the final result
  // const expectedLeft = Field(10);
  // const expectedRight = Field(30);
  // const vkRoot = Poseidon.hash([vkLeaf1.hash, vkLeaf2.hash]);

  // console.log("\nValidation:");
  // console.log("Expected left:", expectedLeft.toString());
  // console.log("Actual left:", proofMerged.publicOutput.left.toString());
  // console.log("Expected right:", expectedRight.toString());
  // console.log("Actual right:", proofMerged.publicOutput.right.toString());

  // if (
  //   proofMerged.publicOutput.left.equals(expectedLeft).toBoolean() &&
  //   proofMerged.publicOutput.right.equals(expectedRight).toBoolean()
  // ) {
  //   console.log("✅ Test passed: Merger successfully combined the proofs!");
  // } else {
  //   console.error("❌ Test failed: Final output doesn't match expected values");
  // }
}

await main();
