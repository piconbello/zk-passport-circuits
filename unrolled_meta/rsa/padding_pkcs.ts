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
  const keySize = StaticType._bitSize;
  const numLimbs = StaticType._numLimbs;
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
