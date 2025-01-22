import {
  Bytes,
  Crypto,
  createForeignCurve,
  Provable,
  Struct,
  UInt32,
  ZkProgram,
  createEcdsa,
} from "o1js";
import {
  Bytes65,
  DG1_TD3,
  LDS_256,
  SIGNED_ATTRS,
  SIGNED_ATTRS_256,
  Static65,
  TBS,
} from "./constants";
import { Hash256Proof } from "./hash256";
import { DynamicSHA2, SHA2 } from "@egemengol/mina-credentials/dynamic";
import {
  assertSubarray,
  parseECpubkey256Uncompressed,
  parseECpubkey256UncompressedDynamic,
} from "./utils";
import { Bigint4096, Rsa4096Proof, Rsa4096State } from "./rsa";
import { Hash512Proof } from "./hash512";
import { mapObject } from "../tests/common";

export class PublicKey_Secp256r1 extends createForeignCurve(
  Crypto.CurveParams.Secp256r1,
) {}
export class Signature_Secp256r1 extends createEcdsa(PublicKey_Secp256r1) {}

export class Tail_Secp256r1_512_Input extends Struct({
  signedAttrs: SIGNED_ATTRS,
  // documentRSA: Rsa4096State,
  // masterRSA: Rsa4096State,
  masterPubkey: PublicKey_Secp256r1,
}) {}

export const Tail_Secp256r1_512 = ZkProgram({
  name: "secp256r1-sha512",
  publicInput: Tail_Secp256r1_512_Input,

  methods: {
    validateTail: {
      privateInputs: [
        UInt32,
        TBS,
        // UInt32, Rsa4096Proof, TBS, Hash512Proof, Rsa4096Proof
      ],

      async method(
        inp: Tail_Secp256r1_512_Input,
        indexPubkeyInTBS: UInt32,
        // docRSA: Rsa4096Proof,
        tbs: TBS,
        // hashProof: Hash512Proof,
        // masterRSA: Rsa4096Proof,
      ) {
        // signedAttrsDigest is of length 64
        const signedAttrsDigest = DynamicSHA2.hash(512, inp.signedAttrs);
        const local_pubkey = parseECpubkey256UncompressedDynamic(
          tbs,
          indexPubkeyInTBS,
        );

        //
      },
    },
    validateTail2: {
      privateInputs: [
        UInt32,
        TBS,
        Bytes65,
        // UInt32, Rsa4096Proof, TBS, Hash512Proof, Rsa4096Proof
      ],

      async method(
        inp: Tail_Secp256r1_512_Input,
        indexPubkeyInTBS: UInt32,
        // docRSA: Rsa4096Proof,
        tbs: TBS,
        pubkeySerial: Bytes65,
        // hashProof: Hash512Proof,
        // masterRSA: Rsa4096Proof,
      ) {
        // signedAttrsDigest is of length 64
        const signedAttrsDigest = DynamicSHA2.hash(512, inp.signedAttrs);
        const local_pubkey = parseECpubkey256Uncompressed(pubkeySerial);
        // const local_pubkey = parseECpubkey256UncompressedDynamic(
        //   tbs,
        //   indexPubkeyInTBS,
        // );
        const staticPubkey = Static65.from(pubkeySerial.bytes);

        tbs.assertContains(staticPubkey);
        //
      },
    },
  },
});

console.log(
  mapObject(await Tail_Secp256r1_512.analyzeMethods(), (m) => m.summary()),
);
