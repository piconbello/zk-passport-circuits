import { DynamicBytes } from "@egemengol/mina-credentials";
import { Field, ZkProgram, Poseidon } from "o1js";
import { ProvableBigint2048 } from "./constants";
import { parseRSAPubkey } from "../../unrolled_meta/rsa/parsing";
import { TBS } from "../constants";
import type { ZkProgramMethods } from "../../unrolled_meta/interface";
import { Out } from "../../unrolled_meta/out";
import { hashBytewisePoseidon } from "../utils";

class Pubkey extends DynamicBytes({ maxLength: 270 }) {}

export const RSA_KeyParser_2048_Methods: ZkProgramMethods = {
  parseKey: {
    privateInputs: [TBS, Pubkey],
    async method(cert: Pubkey, offset: Field): Promise<{ publicOutput: Out }> {
      const { modulus: N, exponentValue: e } = parseRSAPubkey(
        ProvableBigint2048,
        cert,
        offset,
      );

      return {
        publicOutput: new Out({
          left: Poseidon.hash([...N.toFields(), e]),
          right: Field(0), //hashBytewisePoseidon(cert),
          vkDigest: Field(0),
        }),
      };
    },
  },
};

export const RSA_KeyParser_2048 = ZkProgram({
  name: "rsa-keyparser-2048",
  publicOutput: Out,
  methods: RSA_KeyParser_2048_Methods,
});

import { mapObject } from "../../tests/common";
console.log(
  mapObject(
    await RSA_KeyParser_2048.analyzeMethods(),
    (m) => m.summary()["Total rows"],
  ),
);

// 3082010a0282010100d78807caf1065adc837293905b34d68ddbff0f3aaba28f97c184598234bbca3bd1bf483ad1303a0bca2286f2a02e48e9756a4f69f09eabe62b71828bdb856ee2c32b37e9f16c895ed495697053fde1bf3558c5b071353af0c4de146951c64529e98cf17acd9e9f95d8f22b7ba3dac95a3ed277e3cf2e50ff9ef5d17fd54928d5206ba371a4023f404b55a2038329cae1532f873031ad776b8e4c87033200e6cd1dc2c1af856f0fe63d42659f8443f6e0ea9b578bf91e054b7ad82cc19ceaf9744c7d869eb0de5ea163fc83d7052954ed2825e675dd90d6b40896170640c94f51f528351a5f2c27b3f7e4f720c7b11fc0be2b9efe52596b3d9c8ada305270500b0203010001
