import type { DynamicBytes } from "@egemengol/mina-credentials/dynamic";
import { Gadgets, Field, Provable, UInt8 } from "o1js";
import { RsaLimbs4096 } from "./rsa4096";

function assertLessThan16(i: Field, x: Field) {
  Gadgets.rangeCheck16(Field(x).sub(1).sub(i).seal());
}

/**
 * Adds a byte value to the appropriate limb(s) at the specified bit position
 *
 * @param limbs - The array of limbs (116-bit Field elements)
 * @param byte - The byte value to add
 * @param bitPos - The absolute bit position where this byte should be placed
 */
export function addByteToLimbs(
  limbs: Field[],
  byte: Field,
  bitPos: number,
): void {
  // Determine which limb(s) this byte affects
  // Each limb is 116 bits, so we divide by 116 to find the limb index
  const limbIndex1 = Math.floor(bitPos / 116);

  // A byte is 8 bits, so check if it crosses a limb boundary
  const limbIndex2 = Math.floor((bitPos + 7) / 116);

  // Calculate the bit offset within the first limb
  const bitOffset1 = bitPos % 116;

  // Calculate the multiplier needed to place the byte at the correct position in the limb
  const multiplier1 = 2n ** BigInt(bitOffset1);

  if (limbIndex1 === limbIndex2) {
    // Case 1: The byte fits entirely within a single limb
    // Simply multiply by the appropriate power of 2 and add to the limb
    limbs[limbIndex1] = limbs[limbIndex1].add(byte.mul(Field(multiplier1)));
  } else {
    // Case 2: The byte straddles two limbs
    // We need to split it into two parts and add each part to the appropriate limb

    // Calculate how many bits go into the first limb
    const bitsInFirstLimb = 116 - bitOffset1;

    // Use witnesses to split the byte efficiently in the circuit
    const lowPart = Provable.witness(UInt8, () => {
      const byteValue = Number(byte.toBigInt());
      // The lower part is the remainder when divided by 2^bitsInFirstLimb
      return UInt8.from(byteValue % (1 << bitsInFirstLimb));
    });

    const highPart = Provable.witness(UInt8, () => {
      const byteValue = Number(byte.toBigInt());
      // The higher part is the quotient when divided by 2^bitsInFirstLimb
      return UInt8.from(Math.floor(byteValue / (1 << bitsInFirstLimb)));
    });

    // Enforce the constraint that lowPart and highPart correctly reconstruct the original byte
    // This is critical for circuit validity
    const twoToBitsInFirstLimb = Field(2n ** BigInt(bitsInFirstLimb));
    byte.assertEquals(
      lowPart.value.add(highPart.value.mul(twoToBitsInFirstLimb)),
    );

    // Add the contributions to their respective limbs
    // The low part goes in the first limb at position bitOffset1
    limbs[limbIndex1] = limbs[limbIndex1].add(
      lowPart.value.mul(Field(multiplier1)),
    );

    // The high part goes in the second limb at position 0
    limbs[limbIndex2] = limbs[limbIndex2].add(highPart.value);
  }
}

/**
 * Converts a big-endian encoded RSA modulus into an array of 36 limbs of 116 bits each
 * to support efficient circuit computations. This representation is needed because
 * o1js (and ZK systems generally) can't directly handle the full 4096-bit RSA modulus.
 *
 * @param enc - The RSA modulus as a ModulusBytes object (big-endian encoded)
 * @returns An array of 36 Field elements, each representing a 116-bit limb
 */
export function parseModulusIntoLimbs(enc: DynamicBytes, offset: Field) {
  // We expect a 4096-bit modulus (512 bytes)
  assertLessThan16(offset.add(512), enc.length);

  // Initialize all limbs to zero - we'll build them incrementally
  const limbFields = [];
  for (let i = 0; i < 36; i++) {
    limbFields.push(Field(0));
  }
  const limbs = RsaLimbs4096.fromFields(limbFields);

  // We process byte-by-byte in reverse order because:
  // 1. The modulus is stored big-endian (most significant byte first)
  // 2. We're building limbs in little-endian format (least significant bits in limb 0)
  for (let byteIndex = 0; byteIndex < 512; byteIndex++) {
    const byte = enc.getOrUnconstrained(offset.add(byteIndex)).value;

    // Convert from big-endian byte position to absolute bit position
    const reversedByteIndex = 511 - byteIndex;
    const bitPos = reversedByteIndex * 8;

    addByteToLimbs(limbs, byte, bitPos);
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
export function parseExponent(enc: DynamicBytes, offset: Field) {
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
