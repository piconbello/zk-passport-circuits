import { Field, Poseidon, Provable, Struct, ZkProgram, Bytes } from "o1js";
import { DG1_TD3 } from "./constants";
import { SHA2 } from "@egemengol/mina-credentials/dynamic";
import { Out } from "../unrolled_meta/out";

export const DocSign_256r1 = ZkProgram({
  name: "docsign-256r1",
  publicOutput: Out,

  methods: {
    verifySign: {
      privateInputs: [DG1_TD3],
      async method(dg1: DG1_TD3) {
        const dg1Digest: Bytes = SHA2.hash(256, dg1);
        const dg1DigestDigest = Poseidon.hash(
          dg1Digest.bytes.map((uint) => uint.value),
        );

        const initstate_256 = new LdsDigestState_256(
          LdsDigestState_256.initial(),
        );

        return {
          publicOutput: new Out({
            left: Poseidon.hash(dg1.bytes.map((u8) => u8.value)),
            right: Poseidon.hash([dg1DigestDigest, initstate_256.hash()]),
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});
