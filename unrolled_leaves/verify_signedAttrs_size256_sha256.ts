import { Field, Poseidon, Struct, ZkProgram } from "o1js";
import {
  Bytes65,
  EcdsaSecp256r1,
  Field3,
  Secp256r1,
  SIGNED_ATTRS_256,
} from "./constants";
import { SHA2 } from "@egemengol/mina-credentials/dynamic";
import { Out } from "../unrolled_meta/out";
import { bytes32ToScalar, parseECpubkey256Uncompressed } from "./utils";
// import { mapObject } from "../tests/common";

export class VerifySignedAttrs_size256_sha256_Input extends Struct({
  signedAttrs: SIGNED_ATTRS_256,
  pubkeySerial: Bytes65,
  signature_r: Field3,
  signature_s: Field3,
}) {}

export const VerifySignedAttrs_size256_sha256 = ZkProgram({
  name: "verify-signedattrs-size256-sha256",
  publicOutput: Out,

  methods: {
    verifySign: {
      privateInputs: [VerifySignedAttrs_size256_sha256_Input],
      async method(inp: VerifySignedAttrs_size256_sha256_Input) {
        /// Pubkey
        const pubkeyXY = parseECpubkey256Uncompressed(inp.pubkeySerial);
        const pubkey = new Secp256r1(pubkeyXY);

        /// Payload
        const signedAttrsShaDigest = SHA2.hash(256, inp.signedAttrs);
        const aff = bytes32ToScalar(signedAttrsShaDigest.bytes);

        /// Signature
        const signature = new EcdsaSecp256r1({
          // @ts-ignore Field[] is of length 3
          r: inp.signature_r.array,
          // @ts-ignore Field[] is of length 3
          s: inp.signature_s.array,
        });
        // @ts-ignore [Field, Field, Field] is castable to AlmostForeignField
        const isValid = signature.verifySignedHash(aff, pubkey);
        isValid.assertTrue();

        /// Commitment
        const left = Poseidon.hash(inp.signedAttrs.bytes.map((u8) => u8.value));
        const right = Poseidon.hash(
          inp.pubkeySerial.bytes.map((u8) => u8.value),
        );

        return {
          publicOutput: new Out({
            left,
            right,
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});

// await VerifySignedAttrs_size256_sha256.compile();
// console.log(
//   mapObject(await VerifySignedAttrs_size256_sha256.analyzeMethods(), (m) =>
//     m.summary(),
//   ),
// );
