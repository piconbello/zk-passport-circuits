import { Provable, Struct, ZkProgram } from "o1js";
import { DG1_TD3, LDS_256, SIGNED_ATTRS_256 } from "./constants";
import { Hash256Proof } from "./hash256";
import { DynamicSHA2, SHA2 } from "@egemengol/mina-credentials/dynamic";
import { assertSubarray } from "./utils";

export const DIGEST_SIZE = 32; // sha256
export const OFFSET_DG1_IN_LDS = 29; // fixed for sha256
export const OFFSET_LDS_IN_SIGNEDATTRS = 42; // fixed for sha256

export class Head256Input extends Struct({
  dg1: DG1_TD3,
  signedAttrs: SIGNED_ATTRS_256,
}) {}

export const Head256 = ZkProgram({
  name: "head256",
  publicInput: Head256Input,

  methods: {
    validateHead: {
      privateInputs: [LDS_256, Hash256Proof],

      async method(inp: Head256Input, lds: LDS_256, hashProof: Hash256Proof) {
        const dg1Digest = SHA2.hash(256, inp.dg1);
        lds.length.assertGreaterThan(OFFSET_DG1_IN_LDS + DIGEST_SIZE);
        assertSubarray(
          lds.array,
          dg1Digest.bytes,
          DIGEST_SIZE,
          OFFSET_DG1_IN_LDS,
          "dg1 in lds",
        );

        const hashFinalState = hashProof.publicOutput;
        const ldsDigest = DynamicSHA2.validate(256, hashFinalState, lds);
        assertSubarray(
          inp.signedAttrs.bytes,
          ldsDigest.bytes,
          DIGEST_SIZE,
          OFFSET_LDS_IN_SIGNEDATTRS,
          "lds in signedAttrs",
        );

        hashProof.verify();
      },
    },
  },
});

export class Head256Proof extends ZkProgram.Proof(Head256) {}
