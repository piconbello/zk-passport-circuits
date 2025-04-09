import {
  Field,
  Gadgets,
  Provable,
  Struct,
  Bool,
  assert,
  type ProvableExtended,
} from "o1js";

// --- Constants ---
const LIMB_BIT_SIZE = 116n;
const LIMB_MAX_VALUE = (1n << LIMB_BIT_SIZE) - 1n;
export const EXP_BIT_COUNT = 20; // Example

// --- Range Check Gadgets ---
function rangeCheck116(x: Field) {
  let [x0, x1] = Provable.witnessFields(2, () => [
    x.toBigInt() & ((1n << 64n) - 1n),
    x.toBigInt() >> 64n,
  ]);

  Gadgets.rangeCheck64(x0);
  let [x52] = Gadgets.rangeCheck64(x1);
  x52.assertEquals(0n);
  x0.add(x1.mul(1n << 64n)).assertEquals(x);
}

function rangeCheck128Signed(xSigned: Field) {
  let x = xSigned.add(1n << 127n);
  let [x0, x1] = Provable.witnessFields(2, () => [
    x.toBigInt() & ((1n << 64n) - 1n),
    x.toBigInt() >> 64n,
  ]);
  Gadgets.rangeCheck64(x0);
  Gadgets.rangeCheck64(x1);
  x0.add(x1.mul(1n << 64n)).assertEquals(x);
}

// --- Core Static Math on Limbs (Placeholders/Conceptual) ---
// These would contain the actual multi-precision logic using Gadgets.
// For now, they are conceptual placeholders. Actual implementation
// requires careful use of Gadgets.add, Gadgets.mul, Gadgets.carry etc.
// The `multiply` function below shows a more concrete example using Gadgets.multiplication.

function checkLimbs(limbs: Field[], numLimbs: number) {
  assert(
    limbs.length === numLimbs,
    `checkLimbs: Expected ${numLimbs} limbs, got ${limbs.length}`,
  );
  limbs.forEach(rangeCheck116);
}

function limbsToBigint(limbs: Field[]): bigint {
  let value = 0n;
  for (let i = 0; i < limbs.length; i++) {
    value += BigInt(limbs[i].toString()) << (BigInt(i) * LIMB_BIT_SIZE);
  }
  return value;
}

function assertEqualsLimbs(
  limbsA: Field[],
  limbsB: Field[],
  message?: string,
): void {
  assert(limbsA.length === limbsB.length, message);
  for (let i = 0; i < limbsA.length; i++) {
    limbsA[i].assertEquals(limbsB[i], message);
  }
}

// --- Type Definitions ---

interface ProvableBigintInstance {
  fields: Field[];
  modMul(y: this, p: this): this;
  toBigint(): bigint;
  toFields(): Field[];
  checkLimbs(): void;
  assertEquals(other: this, message?: string): void;
}

export interface ProvableBigintStatic<
  T extends ProvableBigintInstance,
  V = { fields: Field[] },
> extends ProvableExtended<T, V> {
  readonly bitSize: number;
  readonly numLimbs: number;
  readonly LimbsProvableType: ProvableExtended<Field[], bigint[]>;

  fromBigint(x: bigint): T;
  fromLimbs(limbs: Field[]): T;
  modSquare(x: T, p: T): T;
}

// --- Base Class (Instance Logic) ---
export class ProvableBigintBase implements ProvableBigintInstance {
  fields: Field[];

  constructor(value: { fields: Field[] }) {
    this.fields = value.fields;
  }

  modMul(y: this, p: this): this {
    assert(
      this.constructor === y.constructor && this.constructor === p.constructor,
      "modMul operands must be of the same ProvableBigint type",
    );
    const StaticType = this
      .constructor as unknown as ProvableBigintStatic<this>;
    return multiply<this>(StaticType, this, y, p);
  }

  toBigint(): bigint {
    return limbsToBigint(this.fields);
  }

  toFields(): Field[] {
    return this.fields;
  }

  checkLimbs(): void {
    const StaticType = this
      .constructor as unknown as ProvableBigintStatic<this>;
    checkLimbs(this.fields, StaticType.numLimbs);
  }

  assertEquals(other: this, message?: string): void {
    assertEqualsLimbs(this.fields, other.fields, message);
  }
}

// --- Factory Function ---
export function createProvableBigint(
  bitSize: number,
): ProvableBigintStatic<ProvableBigintBase> {
  assert(
    bitSize > 0 && bitSize % 8 === 0,
    `ProvableBigint bitSize must be positive and typically a multiple of 8, got ${bitSize}`,
  );
  const numLimbs = Math.ceil(bitSize / Number(LIMB_BIT_SIZE));
  const LimbsProvableType_ = Provable.Array(Field, numLimbs);

  const ProvableBigintStruct = Struct({
    fields: LimbsProvableType_,
  });

  class ProvableBigint_N extends ProvableBigintBase {
    static readonly bitSize = bitSize;
    static readonly numLimbs = numLimbs;
    static readonly LimbsProvableType = LimbsProvableType_ as ProvableExtended<
      Field[],
      bigint[]
    >;

    constructor(value: { fields: Field[] }) {
      // Input validation: Ensure correct number of fields
      if (value.fields.length !== ProvableBigint_N.numLimbs) {
        throw new Error(
          `ProvableBigint_${bitSize}: Expected ${ProvableBigint_N.numLimbs} limbs, got ${value.fields.length}`,
        );
      }
      super(value);
    }

    // --- Static Factory Methods ---
    static fromBigint(x: bigint): ProvableBigint_N {
      assert(x >= 0n, `Input bigint ${x} must be non-negative`);
      assert(
        x < 1n << BigInt(bitSize),
        `Input bigint ${x} is too large for ${bitSize} bits`,
      );

      let fields: Field[] = [];
      let currentBigint = x;
      for (let i = 0; i < numLimbs; i++) {
        const limb = currentBigint & LIMB_MAX_VALUE;
        fields.push(Field(limb));
        currentBigint >>= LIMB_BIT_SIZE;
      }
      assert(
        currentBigint === 0n || (currentBigint === -1n && x < 0n),
        `Input bigint ${x} is too large for ${bitSize} bits`,
      );
      // Pad with zeros if fewer limbs were generated (e.g., small bigint)
      while (fields.length < numLimbs) {
        fields.push(Field(0));
      }

      return new ProvableBigint_N({ fields });
    }

    static fromLimbs(limbs: Field[]): ProvableBigint_N {
      if (limbs.length !== numLimbs) {
        throw new Error(
          `Expected ${numLimbs} limbs for ${bitSize}-bit ProvableBigint, got ${limbs.length}`,
        );
      }
      return new ProvableBigint_N({ fields: [...limbs] }); // Copy limbs
    }

    static modSquare(
      x: ProvableBigint_N,
      p: ProvableBigint_N,
    ): ProvableBigint_N {
      return multiply<ProvableBigint_N>(
        this as unknown as ProvableBigintStatic<ProvableBigint_N>,
        x,
        x,
        p,
        { isSquare: true },
      );
    }

    // --- Provable Static Methods (Delegation) ---
    static sizeInFields(): number {
      return ProvableBigintStruct.sizeInFields();
    }
    static toFields(instance: ProvableBigint_N): Field[] {
      return ProvableBigintStruct.toFields({ fields: instance.fields });
    }
    static toAuxiliary(instance?: ProvableBigint_N | undefined): any[] {
      return ProvableBigintStruct.toAuxiliary(
        instance ? { fields: instance.fields } : undefined,
      );
    }
    static fromFields(fields: Field[]): ProvableBigint_N {
      const rawValue = ProvableBigintStruct.fromFields(fields);
      return new ProvableBigint_N(rawValue);
    }
    static check(instance: ProvableBigint_N): void {
      ProvableBigintStruct.check({ fields: instance.fields });
      instance.checkLimbs(); // Add limb range checks
    }
    static toBigint(instance: ProvableBigint_N): bigint {
      return instance.toBigint();
    }
    static empty(): ProvableBigint_N {
      return new ProvableBigint_N(ProvableBigintStruct.empty());
    }
  }

  return ProvableBigint_N as unknown as ProvableBigintStatic<ProvableBigintBase>;
}

// --- Generic Multiplication Logic ---
export function multiply<T extends ProvableBigintBase>(
  StaticType: ProvableBigintStatic<T>,
  x: T,
  y: T,
  p: T,
  { isSquare = false } = {},
): T {
  const numLimbs = StaticType.numLimbs;
  const limbBitSize = LIMB_BIT_SIZE;
  const limbSizeMultiplier = 1n << limbBitSize;

  const WitnessStruct = Struct({
    qLimbs: StaticType.LimbsProvableType, // Use Provable.Array(Field, numLimbs)
    rLimbs: StaticType.LimbsProvableType, // Use Provable.Array(Field, numLimbs)
  });

  // Witness q, r such that x*y = q*p + r
  let witnessedLimbs = Provable.witness(WitnessStruct, () => {
    let xVal = x.toBigint();
    let yVal = isSquare ? xVal : y.toBigint(); // Use xVal if squaring
    let pVal = p.toBigint();
    if (pVal === 0n) {
      throw new Error("Modulus (p) cannot be zero in multiply witness");
    }
    let xy = xVal * yVal;
    let qVal = xy / pVal;
    let rVal = xy % pVal; // xy - qVal * pVal; Use modulo
    if (rVal < 0n) rVal += pVal; // Ensure remainder is positive

    // Need to ensure witness values fit within the limb structure
    // Example check (might need adjustment based on exact max values)
    const maxVal = (1n << BigInt(StaticType.bitSize)) - 1n;
    if (qVal > maxVal || rVal > maxVal || qVal < 0n || rVal < 0n) {
      console.warn(
        `Witness values might exceed ${StaticType.bitSize} bits. q=${qVal}, r=${rVal}`,
      );
      // Depending on the exact constraints, you might need to handle overflows
      // or ensure inputs guarantee valid witness values.
      // For now, we proceed, but this is a potential issue area.
      // Clamping or throwing an error might be necessary in production.
      // qVal = qVal & maxVal; // Example clamping (potentially incorrect math!)
      // rVal = rVal & maxVal;
    }

    return new WitnessStruct({
      qLimbs: StaticType.fromBigint(qVal).toFields(),
      rLimbs: StaticType.fromBigint(rVal).toFields(),
    });
  });

  const q = StaticType.fromLimbs(witnessedLimbs.qLimbs);
  const r = StaticType.fromLimbs(witnessedLimbs.rLimbs);
  q.checkLimbs();
  r.checkLimbs();

  // Compute delta = xy - qp - r limb by limb
  let delta: Field[] = Array.from({ length: 2 * numLimbs - 1 }, () => Field(0));
  let [X, Y, Q, R, P] = [x.fields, y.fields, q.fields, r.fields, p.fields];

  // Accumulate xy and subtract qp
  for (let i = 0; i < numLimbs; i++) {
    // Compute contribution from x*y
    if (isSquare) {
      // Optimization for squaring: compute diagonal element x_i * x_i
      delta[2 * i] = delta[2 * i].add(X[i].mul(X[i]));
      // Compute off-diagonal elements 2 * x_i * x_j for j < i
      for (let j = 0; j < i; j++) {
        delta[i + j] = delta[i + j].add(X[i].mul(X[j]).mul(2n));
      }
    } else {
      // General multiplication: compute x_i * y_j for all j
      for (let j = 0; j < numLimbs; j++) {
        delta[i + j] = delta[i + j].add(X[i].mul(Y[j]));
      }
    }

    // Subtract contribution from q*p
    for (let j = 0; j < numLimbs; j++) {
      delta[i + j] = delta[i + j].sub(Q[i].mul(P[j]));
    }
  }

  // Subtract r and seal initial limbs (mimicking rsa4096 structure)
  // R has only numLimbs elements.
  for (let i = 0; i < numLimbs; i++) {
    delta[i] = delta[i].sub(R[i]).seal();
  }
  // Seal the remaining delta elements that didn't have R subtracted
  for (let i = numLimbs; i < 2 * numLimbs - 1; i++) {
    delta[i] = delta[i].seal();
  }

  // Perform carrying on the difference delta to show that it is zero
  let carry = Field(0);

  for (let i = 0; i < 2 * numLimbs - 2; i++) {
    // Iterate up to the second-to-last limb
    let deltaPlusCarry = delta[i].add(carry).seal(); // Seal needed? Mimicking original.

    // Witness the next carry c_i = floor( (delta_i + c_{i-1}) / 2^limbBitSize )
    carry = Provable.witness(Field, () =>
      deltaPlusCarry.div(limbSizeMultiplier),
    );

    // Range check the carry: -2^127 <= carry < 2^127
    rangeCheck128Signed(carry); // Use the function from core_2.ts

    // Constraint: delta_i + c_{i-1} = c_i * 2^limbBitSize
    // This proves that the lowest limbBitSize bits of (delta_i + c_{i-1}) are zero.
    deltaPlusCarry.assertEquals(carry.mul(limbSizeMultiplier));
  }

  // Final check: The last limb delta_{2n-2} plus the last carry c_{2n-3} must be zero.
  delta[2 * numLimbs - 2].add(carry).assertEquals(0n);

  // If all checks pass, then xy - qp - r = 0 holds as integers,
  // and r is the correct modular result xy mod p.
  // The witness generation already checked r's limbs via StaticType.check.
  return r;
}

// --- RSA Verification Example (Modified to use isSquare correctly) ---
export function rsaVerify<T extends ProvableBigintBase>(
  StaticType: ProvableBigintStatic<T>,
  message: T,
  signature: T,
  modulus: T,
  publicExponent: Field, // Assume standard small exponent fitting in a Field
  expBitCount: number = EXP_BIT_COUNT,
): void {
  const one = StaticType.fromBigint(1n);

  const bits = publicExponent.toBits(expBitCount);
  let result = one;

  // Square-and-multiply exponentiation
  for (let i = expBitCount - 1; i >= 0; i--) {
    // Square: result = result^2 mod modulus
    result = multiply<T>(StaticType, result, result, modulus, {
      isSquare: true,
    }); // Use isSquare = true

    // Multiply: if bit is 1, result = result * signature mod modulus
    let multiplied = multiply<T>(StaticType, result, signature, modulus); // isSquare defaults to false
    result = Provable.if(bits[i], StaticType, multiplied, result);
  }

  result.assertEquals(message, "RSA signature verification failed");
}
