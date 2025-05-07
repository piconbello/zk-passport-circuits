import { Bool, Bytes, Field, Poseidon } from "o1js";
import type { PerProgram, ZkProgramMethods } from "../unrolled_meta/interface";
import { Bytes32, LDS_256, LDS_256_MAX_LENGTH } from "./constants";
import { DigestState_256 } from "./digest_256";
import { assertSubarray, checkSubarray } from "./utils";
import { Out } from "../unrolled_meta/out";
import { generateCalls as generateDigestCalls } from "./digest_256";
import { sha256 } from "@noble/hashes/sha256";
import { Provable } from "o1js";

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

      // The DG1 digest's starting position in the LDS (Lightweight Data Structure)
      // can vary by a few bytes (0, 1, or 2 from the base OFFSET_DG1_IN_LDS_256)
      // due to ASN.1 DER encoding variations (e.g., short vs. long form for lengths
      // of the overall LDS sequence or the sequence of DG hashes).
      // This loop checks these possible positions to find the actual DG1 digest.
      let atLeastOneMatches = Bool.fromValue(false);
      for (let i = 0; i < 3; i++) {
        const fits = lds.length.greaterThan(OFFSET_DG1_IN_LDS_256 + 32 + i);
        const matches = checkSubarray(
          lds.array,
          dg1Digest.bytes,
          32,
          OFFSET_DG1_IN_LDS_256 + i,
          "dg1Digest in lds",
        );
        atLeastOneMatches = atLeastOneMatches.or(matches.and(fits));
      }
      atLeastOneMatches.assertTrue(
        "dg1Digest needs to be in LDS at one of three pos",
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
    id: "LDS_Verifier_256",
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
