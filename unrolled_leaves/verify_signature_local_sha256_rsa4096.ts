import { Bool, Field, Poseidon, Struct, ZkProgram } from "o1js";
import {
  Bytes65,
  EcdsaSecp256r1,
  Field3,
  Secp256r1,
  SIGNED_ATTRS_256,
  SIGNED_ATTRS_DYNAMIC,
} from "./constants";
import {
  DynamicSHA2,
  SHA2,
  StaticArray,
} from "@egemengol/mina-credentials/dynamic";
import { Out } from "../unrolled_meta/out";
import { bytes32ToScalar, parseECpubkey256Uncompressed } from "./utils";
import Contains from "../unrolled_meta/contains";
import type { ZkProgramMethods } from "../unrolled_meta/interface";
import { PubkeyInCertNeedle } from "./pubkey_in_cert";
import {
  Bigint4096,
  EXP_BIT_COUNT,
  parseRSAfromPkcs1LongLongShort4096,
} from "../unrolled_meta/rsa4096";
// import { mapObject } from "../tests/common";

export class VerifySignature_Local_sha256_rsa4096_Input extends Struct({
  signedAttrs: SIGNED_ATTRS_DYNAMIC,
  pubkeySerial: PubkeyInCertNeedle,
  signature: Bigint4096,
}) {}

export class VerifySignature_Local_sha256_rsa4096_State extends Struct({
  acc: Bigint4096,
  index: Field,
  modulus: Bigint4096,
  signature: Bigint4096,
  exponentValue: Field,
  pubkeySerialDigestDigest: Field,
}) {
  toFields(): Field[] {
    return [
      ...this.acc.fields,
      this.index,
      ...this.modulus.fields,
      ...this.signature.fields,
      this.exponentValue,
      this.pubkeySerialDigestDigest,
    ];
  }
}

const VerifySignature_Local_sha256_RSA4096_Methods: ZkProgramMethods = {
  verifySignature_local_sha256_rsa4096_init: {
    privateInputs: [VerifySignature_Local_sha256_rsa4096_Input],
    async method(inp: VerifySignature_Local_sha256_rsa4096_Input) {
      /// Pubkey
      const parsed = parseRSAfromPkcs1LongLongShort4096(
        inp.pubkeySerial,
        Field(0),
      );
      const signedAttrsShaDigest = DynamicSHA2.hash(256, inp.signedAttrs);

      const left = inp.signedAttrs.hash()
      const state = new VerifySignature_Local_sha256_rsa4096_State({
        acc: Bigint4096.from(0n),
        index: Field(0),
        modulus: new Bigint4096({
          fields: parsed.modulusLimbs,
          value: 0n,
        }),
        signature: inp.signature,
        exponentValue: parsed.exponentValue,
        pubkeySerialDigestDigest:
      })
      const right =

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

export const VerifySignature_Local_sha256_RSA4096 = ZkProgram({
  name: "verify-signature-local-sha256-ec256",
  publicOutput: Out,
  methods: VerifySignature_Local_sha256_RSA4096_Methods,
});
