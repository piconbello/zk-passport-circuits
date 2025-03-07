import { Field, Poseidon, Provable, Struct, ZkProgram, Bytes } from "o1js";
import { DG1_TD3 } from "../constants";
import { SHA2 } from "@egemengol/mina-credentials/dynamic";
import { Out } from "./common";

// TODO maybe use poseidon-safe implementation that encodes length?

export const DigestDG1 = ZkProgram({
  name: "digest-dg1",

  publicOutput: Out,

  methods: {
    td3_256: {
      privateInputs: [DG1_TD3],
      async method(dg1: DG1_TD3) {
        const dg1Digest: Bytes = SHA2.hash(256, dg1);
        const dg1DigestDigest = Poseidon.hash(
          dg1Digest.bytes.map((uint) => uint.value),
        );

        return {
          publicOutput: new Out({
            left: Poseidon.hash(dg1.bytes.map((u8) => u8.value)),
            right: dg1DigestDigest,
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});
