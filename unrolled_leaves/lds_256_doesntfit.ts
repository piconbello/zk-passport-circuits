import { Field, Poseidon, ZkProgram, SelfProof, Bytes, Provable } from "o1js";
import { Bytes32, LDS_256 } from "./constants";
import { DynamicSHA2 } from "@egemengol/mina-credentials/dynamic";
import { assertSubarray } from "./utils";
import type { PerProgram, ZkProgramMethods } from "../unrolled_meta/interface";
import { sha256 } from "@noble/hashes/sha256";
import { analyzeMethods } from "../unrolled_meta/utils";

// TODO maybe use poseidon-safe implementation that encodes length??
export const OFFSET_DG1_IN_LDS_256 = 27;

export const LDS_256_Methods: ZkProgramMethods = {
  processLds: {
    privateInputs: [LDS_256, Bytes32],
    async method(lds: LDS_256, dg1Digest: Bytes32) {
      lds.length.assertGreaterThan(OFFSET_DG1_IN_LDS_256 + 32);
      assertSubarray(
        lds.array,
        dg1Digest.bytes,
        32,
        OFFSET_DG1_IN_LDS_256,
        "dg1Digest in lds",
      );

      const ldsDigest = DynamicSHA2.hash(256, lds);
      return {
        publicOutput: {
          left: Poseidon.hash(dg1Digest.bytes.map((b) => b.value)),
          right: Poseidon.hash(ldsDigest.bytes.map((b) => b.value)),
          vkDigest: Field(0),
        },
      };
    },
  },
};

export function generateCall(
  ldsArr: Uint8Array,
  dg1Arr: Uint8Array,
): PerProgram {
  const dg1Digest = Bytes.from(sha256(dg1Arr));
  const lds = LDS_256.fromBytes(ldsArr);

  return {
    methods: LDS_256_Methods,
    calls: [{ methodName: "processLds", args: [lds, dg1Digest] }],
  };
}

console.log("lds256", await analyzeMethods(LDS_256_Methods));
