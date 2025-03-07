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
import { time } from "../src/timer";

export class Out extends Struct({
  left: Field,
  right: Field,
  vkDigest: Field,
}) {}

export class DynOutProof extends DynamicProof<Undefined, Out> {
  static publicInputType = Undefined;
  static publicOutputType = Out;
  static maxProofsVerified = 1 as const;
  static featureFlags = FeatureFlags.allMaybe;
}

export class DynMidProof extends DynamicProof<Undefined, Out> {
  static publicInputType = Undefined;
  static publicOutputType = Out;
  static maxProofsVerified = 2 as const;
  static featureFlags = FeatureFlags.allMaybe;
}

export const Merger = ZkProgram({
  name: "merger-separate",
  publicOutput: Out,
  methods: {
    acceptLeaf: {
      privateInputs: [DynOutProof, VerificationKey],
      async method(proof: DynOutProof, vk: VerificationKey) {
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
      privateInputs: [
        DynMidProof,
        VerificationKey,
        DynMidProof,
        VerificationKey,
      ],
      async method(
        proofLeft: DynMidProof,
        vkLeft: VerificationKey,
        proofRight: DynMidProof,
        vkRight: VerificationKey,
      ) {
        proofLeft.verify(vkLeft);
        proofRight.verify(vkRight);

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
  name: "leaf-1",
  publicOutput: Out,
  methods: {
    prepare: {
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
  const { verificationKey: vkMerger } = await time("Compiling Merger", () =>
    Merger.compile(),
  );

  const proof1intermediate = await time(
    "Generating Leaf1 prepare proof",
    async () => (await Leaf1.prepare()).proof,
  );
  const proof1 = await time(
    "Generating Leaf1 final proof",
    async () => (await Leaf1.generate(proof1intermediate)).proof,
  );

  console.log("\nLeaf proofs generated:");
  console.log("Leaf1:", proof1.publicOutput.toString());

  const dynLeaf1 = DynOutProof.fromProof(proof1);

  const proofAccept1 = await time(
    "Creating merger proof for Leaf1",
    async () => (await Merger.acceptLeaf(dynLeaf1, vkLeaf1)).proof,
  );

  return;
}

await main();
