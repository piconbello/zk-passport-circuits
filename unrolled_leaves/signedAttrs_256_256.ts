import { Field, Poseidon, Provable, Struct, ZkProgram, Bytes } from "o1js";
import { Bytes32, SIGNED_ATTRS_256 } from "./constants";
import { SHA2 } from "@egemengol/mina-credentials/dynamic";
import { Out } from "../unrolled_meta/out";
import { assertSubarray } from "./utils";
import type { PerProgram, ZkProgramMethods } from "../unrolled_meta/interface";
import { sha256 } from "@noble/hashes/sha256";

// TODO maybe use poseidon-safe implementation that encodes length??

export const OFFSET_LDS_IN_SIGNEDATTRS_256 = 42;

export const SignedAttrs_256_256_Methods: ZkProgramMethods = {
  _256_256: {
    privateInputs: [Bytes32, SIGNED_ATTRS_256],
    async method(ldsDigest: Bytes32, signedAttrs: SIGNED_ATTRS_256) {
      assertSubarray(
        signedAttrs.bytes,
        ldsDigest.bytes,
        32,
        OFFSET_LDS_IN_SIGNEDATTRS_256,
        "ldsDigest in signedAttrs",
      );

      const signedAttrsDigest: Bytes = SHA2.hash(256, signedAttrs);

      return {
        publicOutput: new Out({
          left: Poseidon.hash(ldsDigest.bytes.map((u8) => u8.value)),
          right: Poseidon.hash(signedAttrsDigest.bytes.map((u8) => u8.value)),
          vkDigest: Field(0),
        }),
      };
    },
  },
};

export function generateCall(
  signedAttrs: Uint8Array,
  lds: Uint8Array,
): PerProgram {
  const ldsDigest = Bytes.from(sha256(lds));
  const signedAttrsO1 = SIGNED_ATTRS_256.from(signedAttrs);
  return {
    id: "SignedAttrs_256_256",
    methods: SignedAttrs_256_256_Methods,
    calls: [
      {
        methodName: "_256_256",
        args: [ldsDigest, signedAttrsO1],
      },
    ],
  };
}
