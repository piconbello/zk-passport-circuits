import { Field, Poseidon, Provable, Struct, ZkProgram, Bytes } from "o1js";
import { DG1_TD3 } from "./constants";
import { SHA2 } from "@egemengol/mina-credentials/dynamic";
import { Out } from "../unrolled_meta/out";
import type { PerProgram, ZkProgramMethods } from "../unrolled_meta/interface";
import { DigestState_256 } from "./digest_256";

// TODO maybe use poseidon-safe implementation that encodes length?

export const DG1_TD3_256_Methods: ZkProgramMethods = {
  td3_256: {
    privateInputs: [DG1_TD3],
    async method(dg1: DG1_TD3) {
      const dg1Digest: Bytes = SHA2.hash(256, dg1);
      const dg1DigestDigest = Poseidon.hash(
        dg1Digest.bytes.map((uint) => uint.value),
      );

      const initstate_256 = DigestState_256.initWithCarry(dg1DigestDigest);

      return {
        publicOutput: new Out({
          left: Poseidon.hash(dg1.bytes.map((u8) => u8.value)),
          right: initstate_256.hashPoseidon(),
          vkDigest: Field(0),
        }),
      };
    },
  },
};

export function generateCalls(dg1: Uint8Array): PerProgram {
  const dg1Bytes = DG1_TD3.from(dg1);
  return {
    id: "DG1_TD3_256",
    methods: DG1_TD3_256_Methods,
    calls: [
      {
        methodName: "td3_256",
        args: [dg1Bytes],
      },
    ],
  };
}

export const DG1_TD3_256 = ZkProgram({
  name: "dg1-td3-256",
  publicOutput: Out,
  methods: DG1_TD3_256_Methods,
});
