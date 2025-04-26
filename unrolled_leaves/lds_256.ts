import { Bytes, Field, Poseidon } from "o1js";
import type { PerProgram, ZkProgramMethods } from "../unrolled_meta/interface";
import { Bytes32, LDS_256 } from "./constants";
import { DigestState_256 } from "./digest_256";
import { assertSubarray } from "./utils";
import { Out } from "../unrolled_meta/out";
import { generateCalls as generateDigestCalls } from "./digest_256";
import { sha256 } from "@noble/hashes/sha256";

export const OFFSET_DG1_IN_LDS_256 = 27;

const LDS_Verifier_256_Methods: ZkProgramMethods = {
  verifyLDS: {
    privateInputs: [DigestState_256, LDS_256, Bytes32],
    async method(
      digestState: DigestState_256,
      lds: LDS_256,
      dg1Digest: Bytes32,
    ) {
      digestState.carry.assertEquals(
        Poseidon.hash(dg1Digest.bytes.map((v) => v.value)),
      );

      lds.length.assertGreaterThan(OFFSET_DG1_IN_LDS_256 + 32);
      assertSubarray(
        lds.array,
        dg1Digest.bytes,
        32,
        OFFSET_DG1_IN_LDS_256,
        "dg1Digest in lds",
      );
      const ldsDigest = digestState.validate(lds);
      const ldsDigestFields = ldsDigest.bytes.map((u8) => u8.value);

      return {
        publicOutput: new Out({
          left: digestState.hashPoseidon(),
          right: Poseidon.hash(ldsDigestFields),
          vkDigest: Field(0),
        }),
      };
    },
  },
};

export function generateCalls(
  ldsArr: Uint8Array,
  dg1Arr: Uint8Array,
): PerProgram[] {
  const lds = LDS_256.fromBytes(ldsArr);
  const dg1Digest = Bytes.from(sha256(dg1Arr));
  const carry = Poseidon.hash(dg1Digest.bytes.map((b) => b.value));

  const { perPrograms, state: digestState } = generateDigestCalls(carry, lds);

  const verify: PerProgram = {
    methods: LDS_Verifier_256_Methods,
    calls: [
      {
        methodName: "verifyLDS",
        args: [digestState, lds, dg1Digest],
      },
    ],
  };

  return [...perPrograms, verify];
}
