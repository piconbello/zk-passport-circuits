// parseRSAModulus.ts

import { DynamicBytes, StaticArray } from "@egemengol/mina-credentials";
import { Bool, Field, Provable, UInt32, UInt8 } from "o1js";
import { b64ToBigint, decodeBase64 } from "./parseBundle";
import masterlist_mock from "../files/masterlist_mock.json" with { type: "json" };

const rsaPubkey = masterlist_mock.pairs[1].pubkey;
const encoded: Uint8Array = decodeBase64(rsaPubkey.encoded);
const modulus: bigint = b64ToBigint(rsaPubkey.modulus!);

export class ModulusBytes extends DynamicBytes({ maxLength: 700 }) {}

// export const Limbs = StaticArray(Field, 36);
export const Limbs = Provable.Array(Field, 36);

/**
 * Converts a big-endian encoded RSA modulus into an array of 36 limbs of 116 bits each
 * to support efficient circuit computations. This representation is needed because
 * o1js (and ZK systems generally) can't directly handle the full 4096-bit RSA modulus.
 *
 * @param enc - The RSA modulus as a ModulusBytes object (big-endian encoded)
 * @returns An array of 36 Field elements, each representing a 116-bit limb
 */
export function parseModulusIntoLimbs(enc: ModulusBytes) {
  // We expect a 4096-bit modulus (512 bytes)
  enc.length.assertEquals(512);

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
    const byte = enc.getOrUnconstrained(Field(byteIndex)).value;

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

// export function parseModulusIntoLimbs(bytes: ModulusBytes) {
//   bytes.length.assertEquals(Field(512));

//   const limbs = new Limbs(new Array(36));
//   for (let i = 0; i < 36; i++) {
//     limbs.set(i, Field(0));
//   }

//   for (let byteIndex = 0; byteIndex < 512; byteIndex++) {
//     const byte = bytes.getOrUnconstrained(Field(byteIndex)).value;

//     // Calculate bit position and limb indices
//     const bitPos = byteIndex * 8;
//     const limbIndex1 = Math.floor(bitPos / 116);
//     const limbIndex2 = Math.floor((bitPos + 7) / 116);

//     // Calculate bit offsets within limbs
//     const bitOffset1 = bitPos % 116;

//     // Calculate multipliers (powers of 2)
//     const multiplier1 = 2n ** BigInt(bitOffset1);

//     if (limbIndex1 === limbIndex2) {
//       // Byte fits entirely within one limb
//       limbs.set(
//         limbIndex1,
//         limbs.get(limbIndex1).add(byte.mul(Field(multiplier1))),
//       );
//     } else {
//       // Byte straddles two limbs - need to split it
//       // Calculate how many bits go in the first limb
//       const bitsInFirstLimb = 116 - bitOffset1;

//       // Use witnesses to split the byte
//       const lowPart = Provable.witness(UInt8, () => {
//         // In the prover, compute the low part (bits that go in the first limb)
//         const byteValue = Number(byte.toBigInt());
//         return UInt8.from(byteValue % (1 << bitsInFirstLimb));
//       });

//       const highPart = Provable.witness(UInt8, () => {
//         // In the prover, compute the high part (bits that go in the second limb)
//         const byteValue = Number(byte.toBigInt());
//         return UInt8.from(Math.floor(byteValue / (1 << bitsInFirstLimb)));
//       });

//       // Constrain that lowPart + highPart * 2^bitsInFirstLimb = byte
//       const twoToBitsInFirstLimb = Field(2n ** BigInt(bitsInFirstLimb));
//       byte.assertEquals(
//         lowPart.value.add(highPart.value.mul(twoToBitsInFirstLimb)),
//       );

//       // Add contributions to respective limbs
//       limbs.set(
//         limbIndex1,
//         limbs.get(limbIndex1).add(lowPart.value.mul(Field(multiplier1))),
//       );
//       limbs.set(
//         limbIndex2,
//         limbs.get(limbIndex2).add(highPart.value.mul(Field(1))),
//       );
//     }
//   }

//   return limbs;
// }

///////////////// testing code below

/**
 * Parse a bigint into 36 limbs of 116 bits each (for verification)
 * @param x The bigint value to parse
 * @returns An array of 36 Field elements
 */
export function parseIntoLimbs(x: bigint): Field[] {
  const mask = (1n << 116n) - 1n;
  const fields = [];
  let value = x;
  for (let i = 0; i < 36; i++) {
    fields.push(Field(value & mask));
    value >>= 116n;
  }
  return fields;
}

function testParseModulusIntoLimbs() {
  // Convert the modulus to bytes in little-endian format
  //
  const modulusEncoded = decodeBase64(rsaPubkey.modulus!);
  // const rev = Uint8Array.from(Array.from(modulusEncoded).toReversed());
  const modulusBytes = ModulusBytes.fromBytes(modulusEncoded);
  // const bytesArray = new Uint8Array(512);
  // let tempModulus = modulus;

  // for (let i = 0; i < 512; i++) {
  //   bytesArray[i] = Number(tempModulus & 0xffn);
  //   tempModulus >>= 8n;
  // }

  // const modulusBytes = ModulusBytes.fromBytes(bytesArray);

  // Parse into limbs using our circuit function
  const parsedLimbs = parseModulusIntoLimbs(modulusBytes);

  // Parse using the reference function for verification
  const referenceLimbs = parseIntoLimbs(modulus);

  // Compare the results
  console.log("Comparing parsed limbs with reference limbs:");
  for (let i = 0; i < 36; i++) {
    const parsed = parsedLimbs[i].toString();
    const reference = referenceLimbs[i].toString();
    const matches = parsed === reference;
    console.log(`Limb ${i}: ${matches ? "✓" : "✗"} [${parsed} = ${reference}]`);
  }
}

testParseModulusIntoLimbs();
