import { Field, UInt8, Provable, Poseidon } from "o1js";
import { b64ToBigint, decodeBase64 } from "../../src/parseBundle"; // Assuming this path is correct relative to the test file
import pubkeyObjs from "./parsingStatic.test.json" with { type: "json" };
import { describe, test, expect } from "bun:test";
import {
  parseFromBE,
  exponentToDerFields,
  encodeRsaPubkeyFromParts,
} from "./parsingStatic"; // Import functions to test
import { createProvableBigint } from "./provableBigint";

// --- Test Data Processing ---

const pubkeys = pubkeyObjs.map((obj) => {
  return {
    key_size_bits: obj.key_size_bits,
    encoded: decodeBase64(obj.encoded), // Uint8Array of the full DER
    arr: {
      modulus: decodeBase64(obj.modulus),
      exponent: decodeBase64(obj.exponent),
    },
    bn: {
      modulus: b64ToBigint(obj.modulus),
      exponent: b64ToBigint(obj.exponent),
    },
  };
});

describe("RSA parsing static functions", () => {
  test.each(pubkeys)("parse modulus slice", (keyData) => {
    const StaticBigintType = createProvableBigint(keyData.key_size_bits);
    const modulusEncoded = Array.from(keyData.arr.modulus).map(UInt8.from);
    const calculatedModulusProvable = parseFromBE(
      StaticBigintType,
      modulusEncoded,
    );
    const modulusGot = calculatedModulusProvable.toBigint();
    const modulusExpect = keyData.bn.modulus;
    expect(modulusGot).toEqual(modulusExpect);
  });

  test("serialize exponent of len 3", () => {
    const exp = 0x10001;
    const expected = [3n, 1n, 0n, 1n];
    const gotEncoding = exponentToDerFields(3, Field(exp));
    const got = gotEncoding.map((f) => f.toBigInt());
    expect(got).toEqual(expected);
  });

  test("test first pubkey manually", () => {
    const keyData = pubkeys[0];
    // const StaticBigintType = createProvableBigint(keyData.key_size_bits);
    const modulusEncoded = Array.from(keyData.arr.modulus).map(UInt8.from);
    const exp = Field(keyData.bn.exponent);
    const encoded = encodeRsaPubkeyFromParts(
      keyData.key_size_bits,
      true,
      3,
      modulusEncoded,
      exp,
    );
    const got = Uint8Array.from(encoded.map((f) => Number(f.toBigInt())));
    const expected = keyData.encoded;
    expect(got).toEqual(expected);
  });
});
