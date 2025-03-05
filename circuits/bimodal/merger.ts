import {
  DynamicProof,
  FeatureFlags,
  Field,
  Poseidon,
  Provable,
  SelfProof,
  Struct,
  Undefined,
  VerificationKey,
  ZkProgram,
} from "o1js";
import { Out } from "./common";

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

    // Method for processing a single leaf
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
