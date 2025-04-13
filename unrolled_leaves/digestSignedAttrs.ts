import { DynamicSHA2 } from "@egemengol/mina-credentials";
import type { ZkProgramMethods } from "../unrolled_meta/interface";
import { DynSignedAttrs } from "./constants";
import { hashBytewisePoseidon } from "./utils";
import { Field, Poseidon } from "o1js";

export const Digest_SignedAttrs_256_Methods: ZkProgramMethods = {
  digestSignedAttrs256: {
    privateInputs: [DynSignedAttrs],
    async method(signedAttrs: DynSignedAttrs) {
      const digest = DynamicSHA2.hash(256, signedAttrs);
      return {
        publicOutput: {
          left: hashBytewisePoseidon(signedAttrs),
          right: Poseidon.hash(digest.bytes.map((b) => b.value)),
          vkDigest: Field(0),
        },
      };
    },
  },
};
