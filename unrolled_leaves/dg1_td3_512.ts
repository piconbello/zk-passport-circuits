import { Field, Poseidon, Provable, Struct, ZkProgram, Bytes } from "o1js";
import { DG1_TD3 } from "./constants";
import { SHA2 } from "@egemengol/mina-credentials/dynamic";
import { Out } from "../unrolled_meta/out";
import { LdsDigestState_512 } from "./lds_512";

// TODO maybe use poseidon-safe implementation that encodes length?

export const DG1_TD3_512 = ZkProgram({
  name: "dg1-td3-512",
  publicOutput: Out,

  methods: {
    td3_256: {
      privateInputs: [DG1_TD3],
      async method(dg1: DG1_TD3) {
        const dg1Digest: Bytes = SHA2.hash(512, dg1);
        const dg1DigestDigest = Poseidon.hash(
          dg1Digest.bytes.map((uint) => uint.value),
        );

        const initstate_512 = new LdsDigestState_512(
          LdsDigestState_512.initial(),
        );

        return {
          publicOutput: new Out({
            left: Poseidon.hash(dg1.bytes.map((u8) => u8.value)),
            right: Poseidon.hash([dg1DigestDigest, initstate_512.hash()]),
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});
