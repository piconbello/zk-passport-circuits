import { Field, Poseidon, ZkProgram } from "o1js";
import { Bytes64, SIGNED_ATTRS_512 } from "./constants";
import { Out } from "../unrolled_meta/out";
import { assertSubarray } from "./utils";
import type { ZkProgramMethods } from "../unrolled_meta/interface";

// TODO maybe use poseidon-safe implementation that encodes length??

// TODO different value.
export const OFFSET_LDS_IN_SIGNEDATTRS_512 = 42;

export const SignedAttrs_512_Methods: ZkProgramMethods = {
  ldsDigestInSignedAttrs: {
    privateInputs: [Bytes64, SIGNED_ATTRS_512],
    async method(ldsDigest: Bytes64, signedAttrs: SIGNED_ATTRS_512) {
      assertSubarray(
        signedAttrs.bytes,
        ldsDigest.bytes,
        64,
        OFFSET_LDS_IN_SIGNEDATTRS_512,
        "ldsDigest in signedAttrs",
      );

      return {
        publicOutput: new Out({
          left: Poseidon.hash(ldsDigest.bytes.map((u8) => u8.value)),
          right: Poseidon.hash(signedAttrs.bytes.map((u8) => u8.value)),
          vkDigest: Field(0),
        }),
      };
    },
  },
};

export const SignedAttrs_512 = ZkProgram({
  name: "signedattrs-512",
  publicOutput: Out,
  methods: SignedAttrs_512_Methods,
});
