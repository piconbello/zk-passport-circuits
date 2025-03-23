import { DynamicBytes } from "@egemengol/mina-credentials";
import { Bool, Field, Gadgets, Provable, UInt8 } from "o1js";

function assertLessThan16(i: Field, x: Field) {
  Gadgets.rangeCheck16(Field(x).sub(1).sub(i).seal());
}

export class Encoded extends DynamicBytes({ maxLength: 700 }) {}
export const Limbs = Provable.Array(Field, 36);
export const Exponent = Provable.Array(Bool, 20);

/**
 * Converts a big-endian encoded RSA modulus into an array of 36 limbs of 116 bits each
 * to support efficient circuit computations. This representation is needed because
 * o1js (and ZK systems generally) can't directly handle the full 4096-bit RSA modulus.
 *
 * @param enc - The RSA modulus as a ModulusBytes object (big-endian encoded)
 * @returns An array of 36 Field elements, each representing a 116-bit limb
 */
export function parseModulusIntoLimbs(enc: Encoded, offset: Field) {
  // We expect a 4096-bit modulus (512 bytes)
  assertLessThan16(offset.add(512), enc.length);

  // Initialize all limbs to zero - we'll build them incrementally
  const limbFields = [];
  for (let i = 0; i < 36; i++) {
    limbFields.push(Field(0));
  }
  const limbs = Limbs.fromFields(limbFields);

  // We process byte-by-byte in reverse order because:
  // 1. The modulus is stored big-endian (most significant byte first)
  // 2. We're building limbs in little-endian format (least significant bits in limb 0)
  for (let byteIndex = 0; byteIndex < 512; byteIndex++) {
    const byte = enc.getOrUnconstrained(offset.add(byteIndex)).value;

    // Convert from big-endian byte position to absolute bit position
    const reversedByteIndex = 511 - byteIndex;
    const bitPos = reversedByteIndex * 8;

    // Determine which limb(s) this byte affects - a byte might straddle a limb boundary
    const limbIndex1 = Math.floor(bitPos / 116);
    const limbIndex2 = Math.floor((bitPos + 7) / 116);
    const bitOffset1 = bitPos % 116;
    const multiplier1 = 2n ** BigInt(bitOffset1);

    if (limbIndex1 === limbIndex2) {
      // Simple case: byte fits within a single limb
      limbs[limbIndex1] = limbs[limbIndex1].add(byte.mul(Field(multiplier1)));
    } else {
      // Complex case: byte straddles two limbs, requiring a split
      // We use ZK witnesses to split the byte value efficiently while maintaining constraints
      const bitsInFirstLimb = 116 - bitOffset1;

      const lowPart = Provable.witness(UInt8, () => {
        const byteValue = Number(byte.toBigInt());
        return UInt8.from(byteValue % (1 << bitsInFirstLimb));
      });

      const highPart = Provable.witness(UInt8, () => {
        const byteValue = Number(byte.toBigInt());
        return UInt8.from(Math.floor(byteValue / (1 << bitsInFirstLimb)));
      });

      // Enforce the constraint that the parts correctly reconstruct the original byte
      // This is essential for circuit validity
      const twoToBitsInFirstLimb = Field(2n ** BigInt(bitsInFirstLimb));
      byte.assertEquals(
        lowPart.value.add(highPart.value.mul(twoToBitsInFirstLimb)),
      );

      // Add contributions to the appropriate limbs with correct scaling
      limbs[limbIndex1] = limbs[limbIndex1].add(
        lowPart.value.mul(Field(multiplier1)),
      );
      limbs[limbIndex2] = limbs[limbIndex2].add(highPart.value);
    }
  }

  return limbs;
}

/**
 * Parses an RSA exponent from DER encoding.
 * Takes a length byte followed by up to 3 bytes of exponent data.
 * Returns the exponent as a 20-bit array (standard RSA exponents like 65537 fit here)
 *
 * @param enc - The encoded bytes containing the exponent
 * @param offset - The position in the encoded bytes where the exponent length byte starts
 * @returns An array of 20 Bool values representing the exponent bits
 */
export function parseExponent(enc: Encoded, offset: Field) {
  // Read exponent length (1 byte)
  const expLength = enc.getOrUnconstrained(offset).value;

  // Read up to 3 bytes of exponent data
  let exponentValue = Field(0);

  // We use Provable.if to conditionally read bytes based on the length
  // Start at offset + 1 (after the length byte)
  const startPos = offset.add(1);

  // For 1-byte exponent (usually when exponent is 3)
  const byte1 = enc.getOrUnconstrained(startPos).value;
  exponentValue = Provable.if(
    expLength.greaterThanOrEqual(Field(1)),
    byte1,
    exponentValue,
  );

  // For 2-byte exponent (uncommon)
  const byte2 = enc.getOrUnconstrained(startPos.add(1)).value;
  exponentValue = Provable.if(
    expLength.greaterThanOrEqual(Field(2)),
    exponentValue.add(byte2.mul(Field(256))), // byte2 * 2^8
    exponentValue,
  );

  // For 3-byte exponent (typical for 65537 = 0x010001)
  const byte3 = enc.getOrUnconstrained(startPos.add(2)).value;
  exponentValue = Provable.if(
    expLength.greaterThanOrEqual(Field(3)),
    exponentValue.add(byte3.mul(Field(65536))), // byte3 * 2^16
    exponentValue,
  );

  return exponentValue;
}

export function parseRSAfromDERLongLongShort4096(enc: Encoded) {
  // HEADER PARSING
  let cursor: Field = Field(0);

  // SEQUENCE tag
  enc.getOrUnconstrained(cursor).assertEquals(UInt8.from(48));
  cursor = cursor.add(1);

  // Long form length header
  enc.getOrUnconstrained(cursor).assertEquals(UInt8.from(130));
  cursor = cursor.add(1);

  // Skip sequence length bytes (2 bytes)
  cursor = cursor.add(2);

  // INTEGER tag for modulus
  enc.getOrUnconstrained(cursor).assertEquals(UInt8.from(2));
  cursor = cursor.add(1);

  // Long form length header for modulus
  enc.getOrUnconstrained(cursor).assertEquals(UInt8.from(130));
  cursor = cursor.add(1);

  // Read modulus length (2 bytes)
  const modulusLengthHigh = enc.getOrUnconstrained(cursor).value;
  cursor = cursor.add(1);
  const modulusLengthLow = enc.getOrUnconstrained(cursor).value;
  cursor = cursor.add(1);

  let modulusLength = modulusLengthHigh.mul(256).add(modulusLengthLow);

  // Check for leading zero to handle sign bit (branchless)
  const modulusHead = enc.getOrUnconstrained(cursor);
  const hasLeadingZero = modulusHead.value.equals(Field(0));
  cursor = cursor.add(hasLeadingZero.toField());
  modulusLength = modulusLength.sub(hasLeadingZero.toField());

  // Verify modulus is 512 bytes (4096 bits)
  modulusLength.assertEquals(Field(512));

  const modulusLimbs = parseModulusIntoLimbs(enc, cursor);
  cursor = cursor.add(512);

  // EXPONENT PARSING
  // INTEGER tag for exponent
  enc.getOrUnconstrained(cursor).assertEquals(UInt8.from(2));
  cursor = cursor.add(1);

  const exponentValue = parseExponent(enc, cursor);
  const exponentBits = Exponent.fromValue(exponentValue.toBits(20));
  return {
    modulusLimbs,
    exponentBits,
  };
}
