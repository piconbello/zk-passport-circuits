import type { DynamicBytes } from "@egemengol/mina-credentials/dynamic";
import { Gadgets, Field, Provable, UInt8, assert } from "o1js";
import type {
  ProvableBigintBase,
  ProvableBigintStatic,
} from "./provableBigint";

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
 * Converts a big-endian encoded RSA modulus into a ProvableBigint instance.
 *
 * @template T - The specific ProvableBigint type (e.g., ProvableBigint2048).
 * @param StaticType - The static class (`ProvableBigintStatic`) for the target bigint size.
 * @param enc - The byte array containing the DER-encoded key.
 * @param offset - The starting Field position of the raw modulus bytes within `enc`.
 * @param modulusLengthBytes - The number of bytes in the modulus (e.g., 256 or 512) as a number.
 *                             **Crucially, this must be a plain number**, determined outside the circuit
 *                             based on the DER length bytes, consistent with the passed StaticType.
 * @returns An instance of T representing the parsed modulus.
 */
export function parseModulusIntoLimbs<T extends ProvableBigintBase>(
  StaticType: ProvableBigintStatic<T>,
  enc: DynamicBytes,
  offset: Field,
  modulusLengthBytes: number, // Use number type here based on the explanation above
): T {
  const expectedBytes = StaticType._bitSize / 8;
  if (modulusLengthBytes !== expectedBytes) {
    throw new Error(
      `Modulus length mismatch: Expected ${expectedBytes} bytes for ${StaticType._bitSize}-bit type, but received ${modulusLengthBytes} bytes.`,
    );
  }
  // --- Limb Construction ---
  const currentLimbs = StaticType.empty().fields;

  // Process byte-by-byte in reverse order (big-endian input to little-endian limbs)
  // The loop bound MUST be a constant number for ZK circuit synthesis.
  for (let byteIndex = 0; byteIndex < modulusLengthBytes; byteIndex++) {
    // Read the byte from the DynamicBytes buffer at the correct position.
    // offset is a Field, byteIndex is a number. Use add for Field arithmetic.
    const currentOffset = offset.add(Field(byteIndex));
    const byte = enc.getOrUnconstrained(currentOffset).value;

    // Calculate the absolute bit position for this byte.
    // Since modulusLengthBytes is a number, this calculation happens outside the circuit / during trace generation.
    const reversedByteIndex = modulusLengthBytes - 1 - byteIndex;
    const bitPos = reversedByteIndex * 8;

    // Add this byte's value to the appropriate limb(s).
    // addByteToLimbs modifies currentLimbs in place.
    addByteToLimbs(currentLimbs, byte, bitPos);
  }

  // --- Final Result ---
  // Create the ProvableBigint instance from the constructed limbs.
  const result = StaticType.fromLimbs(currentLimbs);

  // Perform range checks on the final limbs within the circuit.
  result.checkLimbs();

  return result;
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

/**
 * Parses an RSA public key from PKCS#1 DER encoding (SEQUENCE { modulus INTEGER, exponent INTEGER }).
 * This function is generic and requires the specific ProvableBigint static type
 * corresponding to the expected key size to be passed in.
 * Assumes standard "long long short" length encodings common for RSA keys.
 *
 * @template T - The specific ProvableBigint type (e.g., ProvableBigint2048).
 * @param StaticType - The static class (`ProvableBigintStatic`) for the target bigint size.
 * @param enc - The byte array containing the DER-encoded key.
 * @param startOffset - The starting Field position of the key within `enc`.
 * @returns An object containing the parsed modulus (as type T) and exponent (as Field).
 */
export function parseRSAPubkey<T extends ProvableBigintBase>(
  StaticType: ProvableBigintStatic<T>,
  enc: DynamicBytes,
  startOffset: Field,
): { modulus: T; exponentValue: Field } {
  // HEADER PARSING
  let cursor: Field = startOffset;

  // SEQUENCE tag
  enc
    .getOrUnconstrained(cursor)
    .assertEquals(UInt8.from(48), "Expected SEQUENCE tag (0x30)");
  cursor = cursor.add(1);

  // --- SEQUENCE Length (assuming long form for typical keys) ---
  // Check for long-form length indicator (0x82 means length is in next 2 bytes)
  // Note: Smaller keys *might* use short form or 0x81, this assumes typical > 255 byte total structure
  enc
    .getOrUnconstrained(cursor)
    .assertEquals(
      UInt8.from(130),
      "Expected long-form length indicator (0x82) for SEQUENCE",
    );
  cursor = cursor.add(1);
  // We don't strictly need the sequence length value itself, just skip the length bytes
  cursor = cursor.add(2); // Skip the 2 bytes specifying the sequence length

  // --- Modulus INTEGER ---
  // INTEGER tag for modulus
  enc
    .getOrUnconstrained(cursor)
    .assertEquals(UInt8.from(2), "Expected INTEGER tag (0x02) for modulus");
  cursor = cursor.add(1);

  // Modulus Length (assuming long form for typical keys)
  enc
    .getOrUnconstrained(cursor)
    .assertEquals(
      UInt8.from(130),
      "Expected long-form length indicator (0x82) for modulus length",
    );
  cursor = cursor.add(1);

  // Read modulus length bytes (2 bytes)
  const modulusLengthHigh = enc.getOrUnconstrained(cursor).value;
  cursor = cursor.add(1);
  const modulusLengthLow = enc.getOrUnconstrained(cursor).value;
  cursor = cursor.add(1);

  // Calculate modulus length as a Field
  let modulusLengthField = modulusLengthHigh.mul(256).add(modulusLengthLow);

  // Handle potential leading zero byte for positive integers
  // Read the first byte of the modulus value
  const modulusHead = enc.getOrUnconstrained(cursor);
  const hasLeadingZero = modulusHead.value.equals(Field(0));

  // Adjust cursor and length field if leading zero exists
  cursor = cursor.add(hasLeadingZero.toField()); // Advance cursor by 1 if leading zero
  modulusLengthField = modulusLengthField.sub(hasLeadingZero.toField()); // Decrease length by 1 if leading zero

  // --- ASSERTION: Check consistency with StaticType ---
  // Calculate the expected number of bytes based on the ProvableBigint type provided
  const expectedModulusBytes = StaticType._bitSize / 8;
  assert(
    Number.isInteger(expectedModulusBytes),
    `StaticType.bitSize (${StaticType._bitSize}) must be a multiple of 8`,
  );

  // Assert that the length read from DER matches the expected length for this key size
  modulusLengthField.assertEquals(
    Field(expectedModulusBytes),
    `Modulus length in DER does not match expected ${expectedModulusBytes} bytes for ${StaticType._bitSize}-bit key`,
  );

  // --- Parse Modulus Limbs ---
  // Call the generic parsing function, passing the StaticType and the *expected* (and asserted) length as a number
  const modulus: T = parseModulusIntoLimbs<T>(
    StaticType,
    enc,
    cursor,
    expectedModulusBytes, // Pass the JS number expected length
  );

  // Advance cursor past the modulus bytes
  cursor = cursor.add(expectedModulusBytes);

  // --- EXPONENT PARSING ---
  // INTEGER tag for exponent
  enc
    .getOrUnconstrained(cursor)
    .assertEquals(UInt8.from(2), "Expected INTEGER tag (0x02) for exponent");
  cursor = cursor.add(1);

  // Parse the exponent value (handles short-form length internally)
  const exponentValue = parseExponent(enc, cursor);

  // Note: We don't need to advance the cursor further based on exponent length here,
  // as parseExponent reads the length byte and we only return the value.
  // If subsequent fields were parsed, we'd need to calculate the exponent field length.

  return {
    modulus, // Parsed modulus as type T
    exponentValue, // Parsed exponent as Field
  };
}
