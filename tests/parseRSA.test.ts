import { b64ToBigint, decodeBase64 } from "../src/parseBundle";
import { Field, Provable } from "o1js";
import masterlist_mock from "../files/masterlist_mock.json" with { type: "json" };
import { Encoded, parseRSAfromDERLongLongShort4096 } from "../src/parseRSA";
import { describe, expect, test } from "bun:test";

describe("RSA parsing tests", () => {
  const rsaPubkey = masterlist_mock.pairs[1].pubkey;
  const encoded: Uint8Array = decodeBase64(rsaPubkey.encoded);
  const modulus: bigint = b64ToBigint(rsaPubkey.modulus!);
  const exponent = b64ToBigint(rsaPubkey.exponent!);

  function parseIntoLimbs(x: bigint) {
    const mask = (1n << 116n) - 1n;
    let fields = [];
    let value = x;
    for (let i = 0; i < 36; i++) {
      fields.push(Field(value & mask));
      value >>= 116n;
    }
    return fields;
  }

  test("RSA modulus limbs should match expected values", () => {
    const got = parseRSAfromDERLongLongShort4096(Encoded.fromBytes(encoded));
    const expected = parseIntoLimbs(modulus);

    for (let i = 0; i < 36; i++) {
      const circuitLimb = got.modulusLimbs[i].toBigInt();
      const expectedLimb = expected[i].toBigInt();

      expect(circuitLimb).toBe(expectedLimb);
    }
  });

  test("RSA exponent should match expected value", () => {
    const got = parseRSAfromDERLongLongShort4096(Encoded.fromBytes(encoded));

    // Convert the exponentBits array to a bigint for comparison
    const exponentValue = Provable.witness(Field, () => {
      let value = 0n;
      for (let i = 0; i < got.exponentBits.length; i++) {
        if (got.exponentBits[i].toBoolean()) {
          value |= 1n << BigInt(i);
        }
      }
      return Field(value);
    });

    expect(exponentValue.toBigInt()).toBe(exponent);
  });
});
