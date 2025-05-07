import { Field, Poseidon, Struct } from "o1js";
import type { PerProgram, ZkProgramMethods } from "../unrolled_meta/interface";
import {
  Bytes65,
  EcdsaSecp256r1,
  Field3,
  Secp256r1,
  DynDigest,
  Bytes32,
} from "./constants";
import Contains from "../unrolled_meta/contains";
import { Out } from "../unrolled_meta/out";
import {
  bytes32ToScalar,
  hashBytewisePoseidon,
  parseECpubkey256Uncompressed,
} from "./utils";
import { Provable } from "o1js";
import { p256 } from "@noble/curves/p256";

export class SECPr1_Local_256_256_Input extends Struct({
  signedAttrsDigest: Bytes32,
  pubkeySerial: Bytes65,
  signature_r: Field3,
  signature_s: Field3,
}) {}

export const SECPr1_Local_256_256_Methods: ZkProgramMethods = {
  verifySignature: {
    privateInputs: [SECPr1_Local_256_256_Input],
    async method(inp: SECPr1_Local_256_256_Input) {
      const pubkeyXY = parseECpubkey256Uncompressed(inp.pubkeySerial);
      const pubkey = new Secp256r1(pubkeyXY);
      const signature = new EcdsaSecp256r1({
        // @ts-ignore Field[] is of length 3
        r: inp.signature_r.array,
        // @ts-ignore Field[] is of length 3
        s: inp.signature_s.array,
      });
      const aff = bytes32ToScalar(inp.signedAttrsDigest.bytes);
      // @ts-ignore [Field, Field, Field] is castable to AlmostForeignField
      const isValid = signature.verifySignedHash(aff, pubkey);
      isValid.assertTrue();

      return {
        publicOutput: new Out({
          left: Poseidon.hash(
            inp.signedAttrsDigest.bytes.map((u8) => u8.value),
          ),
          right: Poseidon.hash([
            Poseidon.hash(inp.pubkeySerial.bytes.map((u8) => u8.value)),
            ...Contains.init().toFields(),
          ]),
          vkDigest: Field(0),
        }),
      };
    },
  },
};

export function generateCall(
  signedAttrsDigest: Uint8Array,
  pubkeyEncoded: Uint8Array,
  signature: { r: bigint; s: bigint },
): PerProgram {
  // here using noble or node-forge validate secp256r1 signature please
  // console.log("r", signature.r, "s", signature.s);
  // console.log(Buffer.from(pubkeyEncoded).toString("hex"));
  const nobleSignature = new p256.Signature(signature.r, signature.s);
  // console.log(Buffer.from(signedAttrsDigest).toString("hex"));
  const isValid = p256.verify(nobleSignature, signedAttrsDigest, pubkeyEncoded);
  if (!isValid) {
    throw new Error("Invalid secp256r1 signature (pre-verification failed).");
  }

  const sign = new EcdsaSecp256r1({
    r: signature.r,
    s: signature.s,
  });
  if (pubkeyEncoded.length !== 65) throw new Error("expect 65 length pubkey");
  if (signedAttrsDigest.length !== 32)
    throw new Error("we dont know how to turn bigger input into aff");
  const inp = new SECPr1_Local_256_256_Input({
    signedAttrsDigest: Bytes32.from(signedAttrsDigest),
    pubkeySerial: Bytes65.from(pubkeyEncoded),
    signature_r: Field3.from(sign.r.toFields()),
    signature_s: Field3.from(sign.s.toFields()),
  });
  return {
    id: "SECPr1_Local_256",
    methods: SECPr1_Local_256_256_Methods,
    calls: [{ methodName: "verifySignature", args: [inp] }],
  };
}
