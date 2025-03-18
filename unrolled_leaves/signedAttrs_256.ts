import { Field, Poseidon, Provable, Struct, ZkProgram, Bytes } from "o1js";
import { Bytes32, SIGNED_ATTRS_256 } from "./constants";
import { Out } from "../unrolled_meta/out";
import { assertSubarray } from "./utils";

// TODO maybe use poseidon-safe implementation that encodes length??

export const OFFSET_LDS_IN_SIGNEDATTRS_256 = 42;

export const SignedAttrs_256 = ZkProgram({
  name: "signedattrs-256",
  publicOutput: Out,

  methods: {
    _256: {
      privateInputs: [Bytes32, SIGNED_ATTRS_256],
      async method(ldsDigest: Bytes32, signedAttrs: SIGNED_ATTRS_256) {
        assertSubarray(
          signedAttrs.bytes,
          ldsDigest.bytes,
          32,
          OFFSET_LDS_IN_SIGNEDATTRS_256,
          "ldsDigest in signedAttrs",
        );

        return {
          publicOutput: new Out({
            left: Poseidon.hash(ldsDigest.bytes.map((u8) => u8.value)),
            right: Poseidon.hash(signedAttrs.bytes.map((u8) => u8.value)),
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});
