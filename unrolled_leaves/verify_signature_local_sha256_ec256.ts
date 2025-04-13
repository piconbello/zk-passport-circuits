import { Field, Poseidon, Struct, ZkProgram } from "o1js";
import {
  Bytes65,
  EcdsaSecp256r1,
  Field3,
  Secp256r1,
  SIGNED_ATTRS_256,
  SIGNED_ATTRS_DYNAMIC,
} from "./constants";
import { DynamicSHA2, SHA2 } from "@egemengol/mina-credentials/dynamic";
import { Out } from "../unrolled_meta/out";
import { bytes32ToScalar, parseECpubkey256Uncompressed } from "./utils";
import Contains from "../unrolled_meta/contains";
import type { ZkProgramMethods } from "../unrolled_meta/interface";
// import { mapObject } from "../tests/common";

export class VerifySignature_Local_sha256_EC256_Input extends Struct({
  signedAttrs: SIGNED_ATTRS_DYNAMIC,
  pubkeySerial: Bytes65,
  signature_r: Field3,
  signature_s: Field3,
}) {}

const VerifySignature_Local_sha256_EC256_Methods: ZkProgramMethods = {
  verifySignature_local_sha256_ec256: {
    privateInputs: [VerifySignature_Local_sha256_EC256_Input],
    async method(inp: VerifySignature_Local_sha256_EC256_Input) {
      /// Pubkey
      const pubkeyXY = parseECpubkey256Uncompressed(inp.pubkeySerial);
      const pubkey = new Secp256r1(pubkeyXY);

      /// Payload
      const signedAttrsShaDigest = DynamicSHA2.hash(256, inp.signedAttrs);
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
      const left = inp.signedAttrs.hash();
      const pubkeySerialBytesDigest = Poseidon.hash(
        inp.pubkeySerial.bytes.map((u8) => u8.value),
      );
      const containsStateInit = Contains.init().toFields();
      const right = Poseidon.hash([
        pubkeySerialBytesDigest,
        ...containsStateInit,
      ]);

      return {
        publicOutput: new Out({
          left,
          right,
          vkDigest: Field(0),
        }),
      };
    },
  },
};

export const VerifySignature_Local_sha256_EC256 = ZkProgram({
  name: "verify-signature-local-sha256-ec256",
  publicOutput: Out,
  methods: VerifySignature_Local_sha256_EC256_Methods,
});
