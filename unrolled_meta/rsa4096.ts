/**
 * RSA signature verification with o1js
 */
import type { DynamicBytes } from "@egemengol/mina-credentials";
import type { Bytes } from "o1js";
import {
  Field,
  Gadgets,
  Provable,
  Struct,
  Unconstrained,
  Bool,
  UInt8,
} from "o1js";
import rsaMessageTemplateLimbs from "./rsaMessageTemplateLimbs.json" with { type: "json" };

export { Bigint4096, rsaVerify, EXP_BIT_COUNT };

const mask = (1n << 116n) - 1n;

const EXP_BIT_COUNT = 20;

/**
 * We use 116-bit limbs, which means 36 limbs for 4096-bit numbers as used in RSA.
 */
export const RsaLimbs4096 = Provable.Array(Field, 36);

class Bigint4096 extends Struct({
  fields: RsaLimbs4096,
  value: Unconstrained.withEmpty(0n),
}) {
  modMul(x: Bigint4096, y: Bigint4096) {
    return multiply(x, y, this);
  }

  modSquare(x: Bigint4096) {
    return multiply(x, x, this, { isSquare: true });
  }

  toBigint() {
    return this.value.get();
  }

  toFields() {
    return this.fields;
  }

  static fromBigint(x: bigint) {
    let fields = [];
    let value = x;
    for (let i = 0; i < 36; i++) {
      fields.push(Field(x & mask));
      x >>= 116n;
    }
    return new Bigint4096({ fields, value: Unconstrained.from(value) });
  }

  static fromLimbs(limbs: Field[]) {
    if (limbs.length !== 36) {
      throw new Error("Expected 36 limbs for Bigint4096");
    }

    // Calculate the full bigint value from the limbs
    let value = 0n;
    for (let i = 0; i < 36; i++) {
      value += BigInt(limbs[i].toString()) << BigInt(i * 116);
    }

    return new Bigint4096({
      fields: RsaLimbs4096.fromFields(limbs),
      value: Unconstrained.from(value),
    });
  }

  static override check(x: { fields: Field[] }) {
    for (let i = 0; i < 36; i++) {
      rangeCheck116(x.fields[i]);
    }
  }

  equals(other: Bigint4096): Bool {
    // Compare each field element
    let isEqual = Bool(true);
    for (let i = 0; i < 36; i++) {
      isEqual = isEqual.and(this.fields[i].equals(other.fields[i]));
    }
    return isEqual;
  }
}

/**
 * x*y mod p
 */
function multiply(
  x: Bigint4096,
  y: Bigint4096,
  p: Bigint4096,
  { isSquare = false } = {},
) {
  if (isSquare) y = x;

  // witness q, r so that x*y = q*p + r
  // this also adds the range checks in `check()`
  let { q, r } = Provable.witness(
    // TODO Struct() should be unnecessary
    Struct({ q: Bigint4096, r: Bigint4096 }),
    () => {
      let xy = x.toBigint() * y.toBigint();
      let p0 = p.toBigint();
      let q = xy / p0;
      let r = xy - q * p0;
      return { q: Bigint4096.fromBigint(q), r: Bigint4096.fromBigint(r) };
    },
  );

  // compute delta = xy - qp - r
  // we can use a sum of native field products for each limb, because
  // input limbs are range-checked to 116 bits, and 2*116 + log(2*36-1) = 232 + 6 fits the native field.
  let delta: Field[] = Array.from({ length: 2 * 36 - 1 }, () => Field(0));
  let [X, Y, Q, R, P] = [x.fields, y.fields, q.fields, r.fields, p.fields];

  for (let i = 0; i < 36; i++) {
    // when squaring, we can save constraints by not computing xi * xj twice
    if (isSquare) {
      for (let j = 0; j < i; j++) {
        delta[i + j] = delta[i + j].add(X[i].mul(X[j]).mul(2n));
      }
      delta[2 * i] = delta[2 * i].add(X[i].mul(X[i]));
    } else {
      for (let j = 0; j < 36; j++) {
        delta[i + j] = delta[i + j].add(X[i].mul(Y[j]));
      }
    }

    for (let j = 0; j < 36; j++) {
      delta[i + j] = delta[i + j].sub(Q[i].mul(P[j]));
    }

    delta[i] = delta[i].sub(R[i]).seal();
  }

  // perform carrying on the difference to show that it is zero
  let carry = Field(0);

  for (let i = 0; i < 2 * 36 - 2; i++) {
    let deltaPlusCarry = delta[i].add(carry).seal();

    carry = Provable.witness(Field, () => deltaPlusCarry.div(1n << 116n));
    rangeCheck128Signed(carry);

    // (xy - qp - r)_i + c_(i-1) === c_i * 2^116
    // proves that bits i*116 to (i+1)*116 of res are zero
    deltaPlusCarry.assertEquals(carry.mul(1n << 116n));
  }

  // last carry is 0 ==> all of diff is 0 ==> x*y = q*p + r as integers
  delta[2 * 36 - 2].add(carry).assertEquals(0n);

  return r;
}

function rsaVerify(
  message: Bigint4096,
  signature: Bigint4096,
  modulus: Bigint4096,
  publicExponent: Field,
) {
  const one = Bigint4096.fromBigint(1n);
  const bits = publicExponent.toBits(EXP_BIT_COUNT);
  let x = Provable.if(bits[EXP_BIT_COUNT - 1], signature, one);
  for (let i = EXP_BIT_COUNT - 2; i >= 0; i--) {
    x = modulus.modSquare(x);
    x = modulus.modMul(x, Provable.if(bits[i], signature, one));
  }
  Provable.assertEqual(Bigint4096, message, x);
}

/**
 * Custom range check for a single limb, x in [0, 2^116)
 */
function rangeCheck116(x: Field) {
  let [x0, x1] = Provable.witnessFields(2, () => [
    x.toBigInt() & ((1n << 64n) - 1n),
    x.toBigInt() >> 64n,
  ]);

  Gadgets.rangeCheck64(x0);
  let [x52] = Gadgets.rangeCheck64(x1);
  x52.assertEquals(0n); // => x1 is 52 bits
  // 64 + 52 = 116
  x0.add(x1.mul(1n << 64n)).assertEquals(x);
}

/**
 * Custom range check for carries, x in [-2^127, 2^127)
 */
function rangeCheck128Signed(xSigned: Field) {
  let x = xSigned.add(1n << 127n);

  let [x0, x1] = Provable.witnessFields(2, () => {
    const x0 = x.toBigInt() & ((1n << 64n) - 1n);
    const x1 = x.toBigInt() >> 64n;
    return [x0, x1];
  });

  Gadgets.rangeCheck64(x0);
  Gadgets.rangeCheck64(x1);

  x0.add(x1.mul(1n << 64n)).assertEquals(x);
}

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
function addByteToLimbs(limbs: Field[], byte: Field, bitPos: number): void {
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
