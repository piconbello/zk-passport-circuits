import { Bytes, Field, Poseidon } from "o1js";
import type { PerProgram, ZkProgramMethods } from "../unrolled_meta/interface";
import { Bytes32, Certificate, LDS_256, PubkeyEncodedLong } from "./constants";
import { DigestState_256 } from "./digest_256";
import { assertSubarray, hashBytewisePoseidon } from "./utils";
import { Out } from "../unrolled_meta/out";
import { generateCalls as generateDigestCalls } from "./digest_256";
import { sha256 } from "@noble/hashes/sha256";
import type { PubkeyInCertNeedle } from "./pubkey_in_cert";
import { analyzeMethods } from "../unrolled_meta/utils";

export const OFFSET_DG1_IN_LDS_256 = 27;

const Cert_Verifier_256_Methods: ZkProgramMethods = {
  verifyCertDigest: {
    privateInputs: [DigestState_256, Certificate, PubkeyEncodedLong],
    async method(
      digestState: DigestState_256,
      cert: Certificate,
      pubkey: PubkeyEncodedLong,
    ) {
      const pubkeyDigest = hashBytewisePoseidon(pubkey);
      pubkeyDigest.assertEquals(digestState.carry);

      const certShaDigest = digestState.validate(cert);

      return {
        publicOutput: new Out({
          left: digestState.hashPoseidon(),
          right: Poseidon.hash(certShaDigest.bytes.map((u8) => u8.value)),
          vkDigest: Field(0),
        }),
      };
    },
  },
};

// export function generateCalls(
//   ldsArr: Uint8Array,
//   dg1Arr: Uint8Array,
// ): PerProgram[] {
//   const lds = LDS_256.fromBytes(ldsArr);
//   const dg1Digest = Bytes.from(sha256(dg1Arr));
//   const carry = Poseidon.hash(dg1Digest.bytes.map((b) => b.value));

//   const { perPrograms, state: digestState } = generateDigestCalls(carry, lds);

//   const verify: PerProgram = {
//     methods: LDS_Verifier_256_Methods,
//     calls: [
//       {
//         methodName: "verifyLDS",
//         args: [digestState, lds, dg1Digest],
//       },
//     ],
//   };

//   return [...perPrograms, verify];
// }

console.log(await analyzeMethods(Cert_Verifier_256_Methods));
