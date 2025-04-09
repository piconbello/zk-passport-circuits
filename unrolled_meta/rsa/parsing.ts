import type { DynamicBytes } from "@egemengol/mina-credentials/dynamic";
import { Gadgets, Field, Provable, UInt8 } from "o1js";
import { RsaLimbs4096 } from "./rsa4096";
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
  const expectedBytes = StaticType.bitSize / 8;
  if (modulusLengthBytes !== expectedBytes) {
    throw new Error(
      `Modulus length mismatch: Expected ${expectedBytes} bytes for ${StaticType.bitSize}-bit type, but received ${modulusLengthBytes} bytes.`,
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
 * Converts a big-endian encoded RSA modulus into an array of 36 limbs of 116 bits each
 * to support efficient circuit computations. This representation is needed because
 * o1js (and ZK systems generally) can't directly handle the full 4096-bit RSA modulus.
 *
 * @param enc - The RSA modulus as a ModulusBytes object (big-endian encoded)
 * @returns An array of 36 Field elements, each representing a 116-bit limb
 */
// export function parseModulusIntoLimbs(enc: DynamicBytes, offset: Field) {
//   // We expect a 4096-bit modulus (512 bytes)
//   assertLessThan16(offset.add(512), enc.length);

//   // Initialize all limbs to zero - we'll build them incrementally
//   const limbFields = [];
//   for (let i = 0; i < 36; i++) {
//     limbFields.push(Field(0));
//   }
//   const limbs = RsaLimbs4096.fromFields(limbFields);

//   // We process byte-by-byte in reverse order because:
//   // 1. The modulus is stored big-endian (most significant byte first)
//   // 2. We're building limbs in little-endian format (least significant bits in limb 0)
//   for (let byteIndex = 0; byteIndex < 512; byteIndex++) {
//     const byte = enc.getOrUnconstrained(offset.add(byteIndex)).value;

//     // Convert from big-endian byte position to absolute bit position
//     const reversedByteIndex = 511 - byteIndex;
//     const bitPos = reversedByteIndex * 8;

//     addByteToLimbs(limbs, byte, bitPos);
//   }

//   return limbs;
// }

/**
 * Parses a big-endian encoded RSA modulus from DynamicBytes into a ProvableBigint.
 * Reads `modulusLengthBytes` bytes starting at `offset` from `enc`.
 * Constructs a ProvableBigint suitable for `targetBitSize`.
 *
 * @param enc - The buffer containing the encoded modulus bytes.
 * @param offset - The starting offset of the modulus value bytes in `enc`.
 * @param modulusLengthBytes - The length of the modulus in bytes (as a Field).
 * @param targetBitSize - The expected bit size of the modulus (e.g., 2048 or 4096).
 *                        This determines the number of limbs in the output ProvableBigint.
 * @returns An instance of a ProvableBigintBase subclass representing the modulus.
 */
// export function parseModulusIntoProvableBigint(
//   enc: DynamicBytes,
//   offset: Field,
//   modulusLengthBytes: Field,
//   targetBitSize: number,
// ): ProvableBigintStatic {
//   // Return the base class type

//   // 1. Get the specific ProvableBigint static type (constructor + static props)
//   const ProvableBigintType = createProvableBigint(targetBitSize);
//   const numLimbs = ProvableBigintType.numLimbs;

//   // 2. Witness the modulus length as a JS number for loop control
//   //    and perform out-of-circuit checks during witness generation.
//   const lenNum = Provable.witness(Provable.UInt64, () => {
//     // Use UInt64 for positive length
//     const len = modulusLengthBytes.toBigInt();
//     const off = offset.toBigInt();
//     const encLen = enc.length.toBigInt(); // Assuming enc.length is a Field

//     // Check: Does the read stay within the buffer bounds?
//     if (off < 0n || len <= 0n) {
//       throw new Error(`Invalid offset (${off}) or length (${len})`);
//     }
//     if (off + len > encLen) {
//       throw new Error(
//         `Modulus read range [${off}, ${off + len}) exceeds buffer length ${encLen}`,
//       );
//     }

//     // Check: Is the byte length consistent with the target bit size?
//     // Allow for a potential leading zero byte in DER encoding.
//     const expectedBytesMin = BigInt(targetBitSize / 8);
//     const expectedBytesMax = BigInt(targetBitSize / 8 + 1);
//     if (len < expectedBytesMin || len > expectedBytesMax) {
//       // This might indicate an issue (e.g., wrong key size detected, padding error)
//       // Depending on strictness, could throw or just warn.
//       console.warn(
//         `WARN: Modulus length ${len} bytes is unusual for target ${targetBitSize} bits.`,
//       );
//       // Example: throw new Error(`Modulus length ${len} bytes inconsistent with target ${targetBitSize} bits`);
//     }
//     // Check if length exceeds what fits in the limbs
//     if (len * 8n > BigInt(numLimbs * 116)) {
//       // 116 is LIMB_BIT_SIZE
//       throw new Error(
//         `Modulus length ${len} bytes (${len * 8n} bits) exceeds capacity of ${numLimbs} limbs (${numLimbs * 116} bits)`,
//       );
//     }

//     return Provable.UInt64.from(len); // Return as Provable type for witness
//   });

//   // Convert witnessed length back to a JS number for loop control
//   const len = Number(lenNum.toBigInt());

//   // 3. Initialize limbs array with zeros
//   let limbs: Field[] = Array(numLimbs).fill(Field(0));

//   // 4. Process bytes from `enc` (big-endian) and add them to `limbs` (little-endian)
//   // This loop runs during witness generation primarily, setting up constraints via addByteToLimbs
//   for (let byteIndex = 0; byteIndex < len; byteIndex++) {
//     // Calculate offset for the current byte within the circuit
//     const currentOffset = offset.add(Field(byteIndex));
//     // Get the byte value (or an unconstrained default if out of bounds - though witness check should prevent this)
//     const byteValue = enc.getOrUnconstrained(currentOffset).value;

//     // Calculate the bit position for this byte in the little-endian limb structure
//     // This uses the JS 'len' derived from the witness
//     const reversedByteIndex = len - 1 - byteIndex;
//     const bitPos = reversedByteIndex * 8;

//     // Add the byte to the appropriate limb(s). This function modifies 'limbs' in place
//     // and contains the necessary Provable logic (like splitting bytes across limbs).
//     addByteToLimbs(limbs, byteValue, bitPos);
//   }

//   // 5. Create the ProvableBigint instance from the populated limbs
//   // 'fromLimbs' expects an array of the exact 'numLimbs' length.
//   const modulusBigint = ProvableBigintType.fromLimbs(limbs);

//   // 6. Perform necessary checks on the created instance (optional but recommended)
//   // The static 'check' method usually includes checks on individual limb ranges.
//   ProvableBigintType.check(modulusBigint);

//   // Note: This does not explicitly check if the resulting BigInt value is < 2^targetBitSize.
//   // It relies on the input `modulusLengthBytes` and `addByteToLimbs` logic being correct.
//   // If a strict check is needed, additional logic comparing the limbs to the max value
//   // for `targetBitSize` would be required.

//   return modulusBigint;
// }

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
