import { Field, Poseidon, Bytes, ZkProgram } from "o1js";
import type { ZkProgramMethods } from "../../unrolled_meta/interface";
import { createProvableBigint } from "../../unrolled_meta/rsa/provableBigint";
import {
  encodeRsaPubkeyFromParts,
  parseFromBE,
} from "../../unrolled_meta/rsa/parsingStatic";
import { Out } from "../../unrolled_meta/out";
import { mapObject } from "../../tests/common";

export function getRsaEncodeKeyMethods(
  keySizeBits: number,
  isModulusPrefixedWithZero: boolean,
  exponentByteLength: number,
): ZkProgramMethods {
  class ModulusEncoded extends Bytes(Math.ceil(keySizeBits / 8)) {}
  return {
    encodeKey: {
      privateInputs: [ModulusEncoded, Field],
      async method(modulusEncoded: ModulusEncoded, exponent: Field) {
        const encoded = encodeRsaPubkeyFromParts(
          keySizeBits,
          isModulusPrefixedWithZero,
          exponentByteLength,
          modulusEncoded.bytes,
          exponent,
        );
        return {
          publicOutput: {
            left: Poseidon.hash([
              ...modulusEncoded.bytes.map((b) => b.value),
              exponent,
            ]),
            right: Poseidon.hash(encoded),
            vkDigest: Field(0),
          },
        };
      },
    },
  };
}

const Encode = ZkProgram({
  name: "encode",
  publicOutput: Out,
  methods: getRsaEncodeKeyMethods(4096, false, 3),
});

console.log(
  mapObject(await Encode.analyzeMethods(), (m) => m.summary()["Total rows"]),
);

export function getRsaParseModulusMethods(
  keySizeBits: number,
): ZkProgramMethods {
  class ModulusEncoded extends Bytes(Math.ceil(keySizeBits / 8)) {}
  const ProvableBigintModulus = createProvableBigint(keySizeBits);
  return {
    parseModulus: {
      privateInputs: [ModulusEncoded],
      async method(modulusEncoded: ModulusEncoded) {
        const modulusBigint = parseFromBE(
          ProvableBigintModulus,
          modulusEncoded.bytes,
        );

        return {
          publicOutput: {
            left: Poseidon.hash([...modulusEncoded.bytes.map((b) => b.value)]),
            right: Poseidon.hash(modulusBigint.fields),
            vkDigest: Field(0),
          },
        };
      },
    },
  };
}
const Parse = ZkProgram({
  name: "parse",
  publicOutput: Out,
  methods: getRsaParseModulusMethods(4096),
});

console.log(
  mapObject(await Parse.analyzeMethods(), (m) => m.summary()["Total rows"]),
);
