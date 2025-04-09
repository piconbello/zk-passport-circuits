import type { DynamicBytes } from "@egemengol/mina-credentials/dynamic";
import rsaMessageTemplateLimbs from "./rsaMessageTemplateLimbs.json" with { type: "json" };
import { UInt8, Field, Bytes, assert } from "o1js";
import {
  parseExponent,
  parseModulusIntoLimbs,
  addByteToLimbs,
} from "./parsing";
import type {
  ProvableBigintBase,
  ProvableBigintStatic,
} from "./provableBigint";

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
export function parseRSAfromPkcs1<T extends ProvableBigintBase>(
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
  const expectedModulusBytes = StaticType.bitSize / 8;
  assert(
    Number.isInteger(expectedModulusBytes),
    `StaticType.bitSize (${StaticType.bitSize}) must be a multiple of 8`,
  );

  // Assert that the length read from DER matches the expected length for this key size
  modulusLengthField.assertEquals(
    Field(expectedModulusBytes),
    `Modulus length in DER does not match expected ${expectedModulusBytes} bytes for ${StaticType.bitSize}-bit key`,
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

/**
 * Constructs the PKCS#1 v1.5 padded message for RSA signature verification.
 * EMSA-PKCS1-v1_5 = 0x00 || 0x01 || PS || 0x00 || T
 * Where T is the DER encoding of the DigestInfo (hash algorithm + digest)
 * and PS is padding bytes (0xFF).
 *
 * This function uses pre-computed templates containing the fixed padding and
 * DigestInfo structure, leaving space for the actual digest bytes.
 *
 * @template T - The specific ProvableBigint type (e.g., ProvableBigint2048).
 * @param StaticType - The static class (`ProvableBigintStatic`) for the target bigint size.
 * @param digest - The raw message digest (e.g., SHA256 output) as o1js Bytes.
 * @returns The padded message as an instance of T.
 */
export function rsaMessageFromDigest<T extends ProvableBigintBase>(
  StaticType: ProvableBigintStatic<T>,
  digest: Bytes,
): T {
  const keySize = StaticType.bitSize;
  const numLimbs = StaticType.numLimbs;
  let hashAlgoName: string;
  let digestLength: number;

  if (digest.length === 32) {
    hashAlgoName = "SHA2-256";
    digestLength = 32;
  } else if (digest.length === 64) {
    hashAlgoName = "SHA2-512";
    digestLength = 64;
  } else {
    throw new Error(`Unsupported digest length: ${digest.length}`);
  }

  // Construct the key to look up the pre-computed template
  const templateKey = `${hashAlgoName},${keySize}`;
  const templateData = (rsaMessageTemplateLimbs.rsa_message_templates as any)[
    templateKey
  ];

  if (!templateData || !templateData.limbs) {
    throw new Error(
      `RSA message template not found for key size ${keySize} and hash ${hashAlgoName}. Ensure rsaMessageTemplateLimbs.json is populated.`,
    );
  }

  const limbsDecimalStrs: string[] = templateData.limbs;

  // Validate template structure
  if (limbsDecimalStrs.length !== numLimbs) {
    throw new Error(
      `Template limb count mismatch for ${templateKey}: Expected ${numLimbs}, got ${limbsDecimalStrs.length}`,
    );
  }

  // --- Initialize limbs from template ---
  // Convert template string values (representing decimal limb values) to Field elements
  const limbs: Field[] = limbsDecimalStrs.map((s) => Field.fromValue(s));
  const templateBigint = StaticType.fromLimbs(limbs).toBigint();
  const templateHex = templateBigint.toString(16).padStart(keySize / 4, "0"); // Pad to full length!
  // console.log(
  //   `    Expected Template Hex (${templateHex.length / 2} bytes): ${templateHex}`,
  // );

  // --- Insert Digest ---
  // In PKCS #1 v1.5 padding for RSA signature verification:
  // EMSA-PKCS1-v1_5 = 00 || 01 || FF ... FF || 00 || DER(DigestInfo(hashAlg, digest))
  // The raw digest bytes are at the *end* of this structure (big-endian view).
  // Our limbs are little-endian. The template has zeros in the lowest limb positions
  // to accommodate the digest. We need to add the digest bytes there.

  // Process each byte of the raw digest
  for (let byteIndex = 0; byteIndex < digestLength; byteIndex++) {
    // Get the byte Field value from the Bytes object
    const byte = digest.bytes[byteIndex].value; // Access value property of UInt8

    // --- THIS IS THE PART TO CHANGE ---
    // Calculate the bit position for this byte.
    // To achieve the correct big-endian order [byte 0][byte 1]...[byte N-1] at the end,
    // byte[N-1] must be at the lowest bit position (0), byte[N-2] at bit 8, etc.
    // byte[0] must be at the highest bit position within the digest area.
    const bitPos = (digestLength - 1 - byteIndex) * 8;
    // --- END OF CHANGE ---

    // Add this byte's value to the appropriate limb(s).
    // addByteToLimbs modifies the `limbs` array in place.
    addByteToLimbs(limbs, byte, bitPos);
  }

  // --- Final Result ---
  // Create the ProvableBigint instance from the constructed limbs.
  const messageBigint = StaticType.fromLimbs(limbs);

  // Perform range checks on the final limbs within the circuit.
  messageBigint.checkLimbs(); // Ensures limbs are within the valid range

  return messageBigint;
}
