import { Field, Gadgets, Poseidon, Provable, UInt8, type Bytes } from "o1js";
import { addByteToLimbs } from "./parsing";
import { createProvableBigint } from "./provableBigint";

export function parseFromBE(
  BigintType: ReturnType<typeof createProvableBigint>,
  encoded: UInt8[],
): InstanceType<typeof BigintType> {
  // We will handle the optional extra leading zero outside.
  const expectedLen = Math.ceil(BigintType._BIT_SIZE / 8);
  if (encoded.length !== expectedLen) {
    throw new Error(`Invalid encoding length for ${BigintType._BIT_SIZE}`);
  }

  const currentLimbs = BigintType.empty().fields;

  // Process byte-by-byte in reverse order (big-endian input to little-endian limbs)
  for (let byteIndex = 0; byteIndex < encoded.length; byteIndex++) {
    const byte = encoded[byteIndex];

    // Since modulusLengthBytes is a number, this calculation happens outside the circuit / during trace generation.
    const reversedByteIndex = encoded.length - 1 - byteIndex;
    const bitPos = reversedByteIndex * 8;
    addByteToLimbs(currentLimbs, byte.value, bitPos);
  }

  const result = BigintType.fromFields(currentLimbs);
  result.checkLimbs();

  return result;
}

export function exponentToDerFields(
  exponentByteLength: number,
  exponent: Field,
): Field[] {
  // Witness the bytes of the exponent in big-endian order
  const byteFields = Provable.witnessFields(exponentByteLength, () => {
    const exp = exponent.toBigInt();
    const bytes: Field[] = [];

    // Extract bytes in big-endian order.
    for (let i = 0; i < exponentByteLength; i++) {
      const shift = BigInt((exponentByteLength - 1 - i) * 8);
      const byteValue = (exp >> shift) & 0xffn; // Mask with 0xFF
      bytes.push(Field(byteValue));
    }

    // Sanity check (outside circuit)
    if (bytes.length !== exponentByteLength) {
      throw new Error(
        `Internal witness error: Expected ${exponentByteLength} bytes, generated ${bytes.length}`,
      );
    }
    return bytes;
  });

  let reconstructedExponent = Field(0);
  for (let i = 0; i < byteFields.length; i++) {
    Gadgets.rangeCheck8(byteFields[i]);
    reconstructedExponent = reconstructedExponent.mul(256n).add(byteFields[i]);
  }
  reconstructedExponent.assertEquals(
    exponent,
    "Exponent byte decomposition mismatch",
  );
  return [Field(exponentByteLength), ...byteFields];
}
/**
 * Constructs the DER structure of an RSA public key from its components and hashes it.
 * Assumes long-form length encoding (0x82 + 2 bytes) for SEQUENCE and modulus INTEGER.
 * Assumes short-form length encoding (1 byte) for exponent INTEGER.
 *
 * @param keySizeBits Static: Size of the RSA key (e.g., 2048).
 * @param isModulusPrefixedWithZero Static: Whether the modulus needed a leading 0x00 byte in DER.
 * @param exponentByteLength Static: Number of bytes used to encode the exponent value (e.g., 3 for 65537).
 * @param modulusEncoded Circuit Var: Array of UInt8 representing the modulus bytes (excluding potential leading zero).
 * @param exponent Circuit Var: The public exponent as a Field.
 * @returns Field: The Poseidon hash of the reconstructed DER encoding.
 */
export function encodeRsaPubkeyFromParts(
  keySizeBits: number, // Static
  isModulusPrefixedWithZero: boolean, // Static
  exponentByteLength: number, // Static
  modulusEncoded: UInt8[], // Circuit variable
  exponent: Field, // Circuit variable
): Field[] {
  // Initial DER structure parts (constants)
  const encoded: Field[] = [
    Field(0x30), // SEQUENCE tag
    Field(0x82), // Long-form length indicator for SEQUENCE
    Field(0), // Placeholder for SEQUENCE length high byte
    Field(0), // Placeholder for SEQUENCE length low byte
    Field(0x02), // INTEGER tag for modulus
    Field(0x82), // Long-form length indicator for modulus
  ];

  const keySizeBytes = Math.ceil(keySizeBits / 8);

  // --- Modulus Length and Optional Leading Zero ---
  if (isModulusPrefixedWithZero) {
    // Length includes the leading zero byte
    const modulusDerLength = BigInt(keySizeBytes + 1);
    encoded.push(
      Field(modulusDerLength >> 8n), // High byte of modulus length
      Field(modulusDerLength & 0xffn), // Low byte of modulus length
      Field(0), // The leading zero byte itself
    );
  } else {
    // Length is just the key size in bytes
    const modulusDerLength = BigInt(keySizeBytes);
    encoded.push(
      Field(modulusDerLength >> 8n), // High byte of modulus length
      Field(modulusDerLength & 0xffn), // Low byte of modulus length
    );
  }

  // --- Modulus Value Bytes ---
  // Map UInt8[] to Field[]
  encoded.push(...modulusEncoded.map((byte) => byte.value));

  // --- Exponent Tag, Length, and Value Bytes ---
  encoded.push(Field(0x02)); // INTEGER tag for exponent
  // exponentToDerFields returns [lengthByte, valueByte1, ...] and adds necessary constraints
  const exponentDerParts = exponentToDerFields(exponentByteLength, exponent);
  encoded.push(...exponentDerParts);

  // --- Calculate and Fill SEQUENCE Length ---
  // The length is the number of bytes *after* the initial 4 header bytes
  // (SEQUENCE Tag, Length Indicator 0x82, Length High, Length Low)
  const sequenceContentLength = encoded.length - 4;

  // Ensure the length fits within two bytes (should always be true for RSA keys)
  if (sequenceContentLength >= 65536) {
    throw new Error("Calculated SEQUENCE content length exceeds 65535 bytes.");
  }

  const sequenceContentLengthBigInt = BigInt(sequenceContentLength);
  encoded[2] = Field(sequenceContentLengthBigInt >> 8n); // High byte of sequence length
  encoded[3] = Field(sequenceContentLengthBigInt & 0xffn); // Low byte of sequence length

  return encoded;
}
