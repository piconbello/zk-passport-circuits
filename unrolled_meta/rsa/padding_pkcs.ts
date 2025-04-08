import type { DynamicBytes } from "@egemengol/mina-credentials/dynamic";
import rsaMessageTemplateLimbs from "./rsaMessageTemplateLimbs.json" with { type: "json" };
import { UInt8, Field, Bytes } from "o1js";
import {
  parseExponent,
  parseModulusIntoLimbs,
  addByteToLimbs,
} from "./parsing";

export function parseRSAfromPkcs1LongLongShort4096(
  enc: DynamicBytes,
  startOffset: Field,
) {
  // HEADER PARSING
  let cursor: Field = startOffset;

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
  return {
    modulusLimbs,
    exponentValue,
  };
}

export function rsaMessageFromDigest(
  digest: Bytes,
  keySizeBits: bigint,
): Field[] {
  if (keySizeBits !== 4096n) throw new Error("not supported yet");

  let limbsDecimalStrs: string[];
  if (digest.length === 32) {
    limbsDecimalStrs =
      rsaMessageTemplateLimbs.rsa_message_templates["SHA2-256,4096"].limbs;
  } else if (digest.length === 64) {
    limbsDecimalStrs =
      rsaMessageTemplateLimbs.rsa_message_templates["SHA2-512,4096"].limbs;
  } else {
    throw new Error("unsupported digest length");
  }
  // Convert template string values to Field elements
  const limbs = limbsDecimalStrs.map((s) => Field.fromValue(s));

  // In PKCS #1 v1.5 padding for RSA signature verification:
  // 1. The digest appears at the end of the padded message
  // 2. Our limbs are stored in little-endian format (least significant bits first)
  // 3. Therefore, the digest should be placed at the beginning of our limbs array
  //    (which corresponds to the end of the message in big-endian format)

  // The template is structured with zeros in the first few limbs precisely
  // to reserve space for the digest to be added

  // Process each byte of the digest
  for (let byteIndex = 0; byteIndex < digest.length; byteIndex++) {
    const byte = digest.bytes.at(byteIndex)!.value;

    // We process the digest in reverse byte order because:
    // 1. The digest is stored in big-endian format (most significant byte first)
    // 2. We need to insert it into our little-endian limb structure
    const reversedByteIndex = digest.length - 1 - byteIndex;

    // Calculate bit position in the overall message
    const bitPos = reversedByteIndex * 8;

    // Add this byte to the appropriate limb(s)
    addByteToLimbs(limbs, byte, bitPos);
  }

  return limbs;
}
