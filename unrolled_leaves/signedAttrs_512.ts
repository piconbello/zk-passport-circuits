import { Field, Poseidon, Provable, Struct, ZkProgram, Bytes } from "o1js";
import { Bytes32, SIGNED_ATTRS_512 } from "./constants";
import { SHA2 } from "@egemengol/mina-credentials/dynamic";
import { Out } from "../unrolled_meta/out";
import { assertSubarray } from "./utils";

// TODO maybe use poseidon-safe implementation that encodes length??

export const OFFSET_LDS_IN_SIGNEDATTRS_512 = 42;

export const SignedAttrs_512 = ZkProgram({
  name: "signedattrs-512",
  publicOutput: Out,

  methods: {
    _512: {
      privateInputs: [Bytes32, SIGNED_ATTRS_512],
      async method(ldsDigest: Bytes32, signedAttrs: SIGNED_ATTRS_512) {
        assertSubarray(
          signedAttrs.bytes,
          ldsDigest.bytes,
          64,
          OFFSET_LDS_IN_SIGNEDATTRS_512,
          "ldsDigest in signedAttrs",
        );

        const signedAttrsDigest: Bytes = SHA2.hash(512, signedAttrs);

        return {
          publicOutput: new Out({
            left: Poseidon.hash(ldsDigest.bytes.map((u8) => u8.value)),
            right: Poseidon.hash(signedAttrsDigest.bytes.map((u8) => u8.value)),
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});
