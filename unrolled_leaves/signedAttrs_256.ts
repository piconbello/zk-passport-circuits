import { Bytes, Field, Poseidon, Provable, ZkProgram } from "o1js";
import { Bytes32, SIGNED_ATTRS_256 } from "./constants";
import { Out } from "../unrolled_meta/out";
import { assertSubarray } from "./utils";
import type { PerProgram, ZkProgramMethods } from "../unrolled_meta/interface";
import { sha256 } from "@noble/hashes/sha256";

// TODO maybe use poseidon-safe implementation that encodes length??

export const OFFSET_LDS_IN_SIGNEDATTRS_256 = 42;

export const SignedAttrs_256_Methods: ZkProgramMethods = {
  ldsDigestInSignedAttrs: {
    privateInputs: [Bytes32, SIGNED_ATTRS_256],
    async method(ldsDigest: Bytes32, signedAttrs: SIGNED_ATTRS_256) {
      assertSubarray(
        signedAttrs.bytes,
        ldsDigest.bytes,
        32,
        OFFSET_LDS_IN_SIGNEDATTRS_256,
        "ldsDigest in signedAttrs",
      );

      const ldsDigestFields = ldsDigest.bytes.map((u8) => u8.value);
      Provable.asProver(() => {
        console.log(
          ">>> ldsDigestInSignedAttrs: Fields for Poseidon Hash (hex):",
          ldsDigestFields.map((f) => f.toBigInt().toString(16)).join(""),
        );
      });

      return {
        publicOutput: new Out({
          left: Poseidon.hash(ldsDigestFields),
          right: Poseidon.hash(signedAttrs.bytes.map((u8) => u8.value)),
          vkDigest: Field(0),
        }),
      };
    },
  },
};

export function generateCalls(
  signedAttrs: Uint8Array,
  lds: Uint8Array,
): PerProgram {
  const ldsDigest = Bytes.from(sha256(lds));
  console.log(
    "in generateCalls",
    Buffer.from(ldsDigest.toBytes()).toString("hex"),
    ldsDigest.toBytes().length,
  );
  const signedAttrsO1 = SIGNED_ATTRS_256.from(signedAttrs);
  return {
    methods: SignedAttrs_256_Methods,
    calls: [
      {
        methodName: "ldsDigestInSignedAttrs",
        args: [ldsDigest, signedAttrsO1],
      },
    ],
  };
}
