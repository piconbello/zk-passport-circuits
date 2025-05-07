import { Bytes, Field, Poseidon, Provable } from "o1js";
import type { PerProgram, ZkProgramMethods } from "../unrolled_meta/interface";
import { Out } from "../unrolled_meta/out";
import { Certificate } from "./constants";
import {
  DigestState_256,
  generateCalls as generateDigestCalls,
} from "./digest_256";
import { sha256 } from "@noble/hashes/sha256";
import { hashBytewisePoseidon } from "./utils";

const CertDigest_256_Methods: ZkProgramMethods = {
  digestCert: {
    privateInputs: [DigestState_256, Certificate],
    async method(digestState: DigestState_256, cert: Certificate) {
      // Provable.asProver(() => {
      //   console.log("cert carry", digestState.carry.toBigInt());
      //   console.log("cert com", digestState.digestState.commitment.toBigInt());
      //   console.log("cert state", digestState.digestState.state.toValue());
      //   console.log("cert left", digestState.hashPoseidon().toBigInt());
      // });
      const certShaDigest = digestState.validate(cert);
      // Provable.asProver(() => {
      //   console.log("state in", digestState.hashPoseidon().toBigInt());
      // });
      Provable.asProver(() => {
        console.log(
          "in digest",
          Buffer.from(certShaDigest.toBytes()).toString("base64"),
        );
        console.log(
          "right",
          Poseidon.hash([
            ...certShaDigest.bytes.map((b) => b.value),
          ]).toBigInt(),
        );
      });

      return {
        publicOutput: new Out({
          left: digestState.hashPoseidon(),
          right: Poseidon.hash([...certShaDigest.bytes.map((b) => b.value)]),
          vkDigest: Field(0),
        }),
      };
    },
  },
};

export function generateCalls(certArr: Uint8Array): PerProgram[] {
  const cert = Certificate.fromBytes(certArr);
  const certPoseidonDigest = hashBytewisePoseidon(cert);
  // const certShaDigest = Bytes.from(sha256(certArr));
  // const certShaDigestPoseidonDigest = Poseidon.hash(
  //   certShaDigest.bytes.map((b) => b.value),
  // );

  const { perPrograms, state: digestState } = generateDigestCalls(
    certPoseidonDigest,
    cert,
  );

  // console.log("state", digestState.hashPoseidon().toBigInt());

  // const lastCalls = perPrograms[perPrograms.length - 1].calls;
  // console.log(lastCalls[lastCalls.length - 1].args);

  const verify: PerProgram = {
    id: "CertDigest_256",
    methods: CertDigest_256_Methods,
    calls: [
      {
        methodName: "digestCert",
        args: [digestState, cert],
      },
    ],
  };

  return [...perPrograms, verify];
}
