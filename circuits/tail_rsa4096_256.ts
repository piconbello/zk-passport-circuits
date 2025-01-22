import { Bytes, Provable, Struct, UInt32, ZkProgram } from "o1js";
import {
  DG1_TD3,
  LDS_256,
  SIGNED_ATTRS,
  SIGNED_ATTRS_256,
  Static65,
  TBS,
} from "./constants";
import { Hash256Proof } from "./hash256";
import { DynamicSHA2, SHA2 } from "@egemengol/mina-credentials/dynamic";
import { assertSubarray } from "./utils";
import { Bigint4096, Rsa4096Proof, Rsa4096State } from "./rsa";
import { Hash512Proof } from "./hash512";

export class Tail_RSA4096_512_Input extends Struct({
  signedAttrs: SIGNED_ATTRS,
  // documentRSA: Rsa4096State,
  // masterRSA: Rsa4096State,
  masterPubkey: Bigint4096,
}) {}

export const Tail_RSA4096_512 = ZkProgram({
  name: "rsa4096-sha512",
  publicInput: Tail_RSA4096_512_Input,

  methods: {
    validateTail: {
      privateInputs: [UInt32, Rsa4096Proof, TBS, Hash512Proof, Rsa4096Proof],

      async method(
        inp: Tail_RSA4096_512_Input,
        indexSignedAttrsInTBS: UInt32,
        docRSA: Rsa4096Proof,
        tbs: TBS,
        hashProof: Hash512Proof,
        masterRSA: Rsa4096Proof,
      ) {
        // signedAttrsDigest is of length 64
        const signedAttrsDigest = DynamicSHA2.hash(512, inp.signedAttrs);
        //
      },
    },
  },
});
