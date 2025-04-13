import {
  Field,
  Gadgets,
  Provable,
  Struct,
  Bool,
  assert,
  type ProvablePure,
} from "o1js";

const LIMB_BIT_SIZE = 116n;
const LIMB_MAX_VALUE = (1n << LIMB_BIT_SIZE) - 1n;
export const EXP_BIT_COUNT = 20;

function rangeCheck116(x: Field) {
  let [x0, x1] = Provable.witnessFields(2, () => [
    x.toBigInt() & ((1n << 64n) - 1n),
    x.toBigInt() >> 64n,
  ]);
  Gadgets.rangeCheck64(x0);
  let [x52] = Gadgets.rangeCheck64(x1);
  x52.assertEquals(0n, "RangeCheck116: Upper 52 bits must be zero");
  x0.add(x1.mul(1n << 64n)).assertEquals(
    x,
    "RangeCheck116: Limb reconstruction failed",
  );
}

function rangeCheck128Signed(xSigned: Field) {
  let x = xSigned.add(1n << 127n);
  let [x0, x1] = Provable.witnessFields(2, () => [
    x.toBigInt() & ((1n << 64n) - 1n),
    x.toBigInt() >> 64n,
  ]);
  Gadgets.rangeCheck64(x0);
  Gadgets.rangeCheck64(x1);
  x0.add(x1.mul(1n << 64n)).assertEquals(
    x,
    "RangeCheck128Signed: Value reconstruction failed",
  );
}

function _checkLimbs(limbs: Field[], numLimbs: number) {
  assert(
    limbs.length === numLimbs,
    `Expected ${numLimbs} limbs, got ${limbs.length}`,
  );
  limbs.forEach(rangeCheck116);
}

function _limbsToBigint(limbs: Field[]): bigint {
  let value = 0n;
  for (let i = 0; i < limbs.length; i++) {
    value += limbs[i].toBigInt() << (BigInt(i) * LIMB_BIT_SIZE);
  }
  return value;
}

function _bigintToLimbs(x: bigint, numLimbs: number, bitSize: number): Field[] {
  assert(x >= 0n, `Input bigint ${x} must be non-negative`);
  const maxVal = 1n << BigInt(bitSize);
  assert(
    x < maxVal,
    `Input bigint ${x} is too large for ${bitSize} bits (max is ${maxVal - 1n})`,
  );
  let fields: Field[] = [];
  let currentBigint = x;
  for (let i = 0; i < numLimbs; i++) {
    const limb = currentBigint & LIMB_MAX_VALUE;
    fields.push(Field(limb));
    currentBigint >>= LIMB_BIT_SIZE;
  }
  assert(
    currentBigint === 0n,
    `_bigintToLimbs: Conversion failed, non-zero remainder ${currentBigint}`,
  );
  while (fields.length < numLimbs) {
    fields.push(Field(0));
  }
  return fields;
}

function _assertEqualsLimbs(
  limbsA: Field[],
  limbsB: Field[],
  message?: string,
): void {
  assert(
    limbsA.length === limbsB.length,
    `_assertEqualsLimbs: Limb arrays must have the same length (${limbsA.length} vs ${limbsB.length})`,
  );
  for (let i = 0; i < limbsA.length; i++) {
    limbsA[i].assertEquals(limbsB[i], message);
  }
}

function _assertNotEqualsLimbs(
  limbsA: Field[],
  limbsB: Field[],
  message?: string,
): void {
  assert(
    limbsA.length === limbsB.length,
    `_assertNotEqualsLimbs: Limb arrays must have the same length (${limbsA.length} vs ${limbsB.length})`,
  );
  let allEqual = Bool(true);
  for (let i = 0; i < limbsA.length; i++) {
    allEqual = allEqual.and(limbsA[i].equals(limbsB[i]));
  }
  allEqual.assertFalse(message);
}

function _multiplyLimbs(
  xLimbs: Field[],
  yLimbs: Field[],
  pLimbs: Field[],
  numLimbs: number,
  bitSize: number,
  LimbsProvableType: ProvablePure<Field[]>,
  { isSquare = false } = {},
) {
  const limbBitSize = LIMB_BIT_SIZE;
  const limbSizeMultiplier = 1n << limbBitSize;

  assert(
    xLimbs.length === yLimbs.length &&
      xLimbs.length === pLimbs.length &&
      xLimbs.length === numLimbs,
    `_multiplyLimbs: Input limb arrays must have length ${numLimbs}`,
  );
  const totalLimbCapacity = numLimbs * Number(LIMB_BIT_SIZE);
  assert(
    bitSize <= totalLimbCapacity,
    `_multiplyLimbs: bitSize (${bitSize}) cannot exceed total limb capacity (${totalLimbCapacity})`,
  );

  const WitnessStruct = Struct({
    qLimbs: LimbsProvableType,
    rLimbs: LimbsProvableType,
  });

  let witnessedLimbs = Provable.witness(WitnessStruct, () => {
    let xVal = _limbsToBigint(xLimbs);
    let yVal = isSquare ? xVal : _limbsToBigint(yLimbs);
    let pVal = _limbsToBigint(pLimbs);
    if (pVal === 0n)
      throw new Error(
        "_multiplyLimbs: Modulus (p) cannot be zero in witness generation",
      );

    let xy = xVal * yVal;
    let qVal = xy / pVal;
    let rVal = xy % pVal;
    if (rVal < 0n) rVal += pVal;

    // Use totalLimbCapacity for witness generation to avoid premature clipping
    let qLimbsWitness = _bigintToLimbs(qVal, numLimbs, totalLimbCapacity);
    let rLimbsWitness = _bigintToLimbs(rVal, numLimbs, totalLimbCapacity); // r should fit bitSize ideally

    return new WitnessStruct({ qLimbs: qLimbsWitness, rLimbs: rLimbsWitness });
  });

  const qLimbs = witnessedLimbs.qLimbs;
  const rLimbs = witnessedLimbs.rLimbs;

  _checkLimbs(qLimbs, numLimbs);
  _checkLimbs(rLimbs, numLimbs); // Check range for result 'r'

  // --- Changes Start Here ---

  // Compute delta = xy - qp - r limb by limb
  // Size should be 2n-1 to hold coefficients up to z^(2n-2)
  let delta: Field[] = Array.from({ length: 2 * numLimbs - 1 }, () => Field(0));
  let [X, Y, Q, R, P] = [xLimbs, yLimbs, qLimbs, rLimbs, pLimbs];

  // Accumulate xy and subtract qp
  for (let i = 0; i < numLimbs; i++) {
    if (isSquare) {
      delta[2 * i] = delta[2 * i].add(X[i].mul(X[i]));
      for (let j = 0; j < i; j++) {
        delta[i + j] = delta[i + j].add(X[i].mul(X[j]).mul(2n));
      }
    } else {
      for (let j = 0; j < numLimbs; j++) {
        // Ensure index i+j does not exceed delta bounds
        if (i + j < delta.length) {
          delta[i + j] = delta[i + j].add(X[i].mul(Y[j]));
        } else if (X[i].mul(Y[j]).toBigInt() !== 0n) {
          // This should ideally not happen if q/r fit numLimbs
          console.warn(
            `WARN: Product term X[${i}]*Y[${j}] overflows delta array.`,
          );
        }
      }
    }
    for (let j = 0; j < numLimbs; j++) {
      // Ensure index i+j does not exceed delta bounds
      if (i + j < delta.length) {
        delta[i + j] = delta[i + j].sub(Q[i].mul(P[j]));
      } else if (Q[i].mul(P[j]).toBigInt() !== 0n) {
        // This should ideally not happen if q/r fit numLimbs
        console.warn(
          `WARN: Quotient term Q[${i}]*P[${j}] overflows delta array.`,
        );
      }
    }
  }

  // Subtract r and seal limbs (mimic old strategy)
  for (let i = 0; i < numLimbs; i++) {
    delta[i] = delta[i].sub(R[i]).seal(); // Seal after subtraction
  }
  // Seal remaining delta elements
  for (let i = numLimbs; i < 2 * numLimbs - 1; i++) {
    delta[i] = delta[i].seal(); // Seal the rest
  }

  // Perform carrying on the difference delta
  let carry = Field(0);
  const limbSizeMultiplierBigint = 1n << limbBitSize; // Keep bigint version for assert check
  const limbSizeMultiplierField = Field(limbSizeMultiplierBigint); // Create Field version for div

  // Loop up to 2n-3 (indices 0 to 2n-3)
  for (let i = 0; i < 2 * numLimbs - 2; i++) {
    // Seal the sum, as per the old working code
    let limbPlusCarry = delta[i].add(carry).seal();

    // Witness the next carry using FIELD division, like the old code
    let nextCarry = Provable.witness(
      Field,
      () => limbPlusCarry.div(limbSizeMultiplierField), // Use Field.div()
    );

    // Range check the resulting carry field element, like the old code
    rangeCheck128Signed(nextCarry);

    // Constraint: delta_i + c_{i-1} = c_i * 2^limbBitSize (verified in the field)
    // Use the bigint multiplier here, assertEquals handles Field(bigint) conversion
    limbPlusCarry.assertEquals(
      nextCarry.mul(limbSizeMultiplierBigint),
      `_multiplyLimbs: Carry propagation check failed at limb index ${i}`,
    );

    // Update carry for the next iteration
    carry = nextCarry;
  }

  // Final check: The last limb delta_{2n-2} plus the last carry c_{2n-3} must be zero.
  delta[2 * numLimbs - 2]
    .add(carry)
    .assertEquals(0n, "_multiplyLimbs: Final carry check failed");

  // --- Changes End Here ---

  return rLimbs; // Return only the remainder limbs
}

export function createProvableBigint(bitSize: number) {
  assert(
    bitSize > 0,
    `createProvableBigint: bitSize must be positive, got ${bitSize}`,
  );
  const numLimbs = Math.ceil(bitSize / Number(LIMB_BIT_SIZE));
  // const actualBitSize = Number(BigInt(numLimbs) * LIMB_BIT_SIZE);

  const LimbsProvableType = Provable.Array(Field, numLimbs);

  class ProvableBigint_N extends Struct({ fields: LimbsProvableType }) {
    static _NUM_LIMBS = numLimbs;
    static _BIT_SIZE = bitSize;
    static _LIMBS_TYPE = LimbsProvableType;

    static fromBigint(x: bigint): ProvableBigint_N {
      const limbs = _bigintToLimbs(x, this._NUM_LIMBS, bitSize);
      return new ProvableBigint_N({ fields: limbs });
    }

    static toBigint(instance: ProvableBigint_N): bigint {
      return _limbsToBigint(instance.fields);
    }

    static assertEquals(
      a: ProvableBigint_N,
      b: ProvableBigint_N,
      message?: string,
    ): void {
      _assertEqualsLimbs(a.fields, b.fields, message);
    }

    static assertNotEquals(
      a: ProvableBigint_N,
      b: ProvableBigint_N,
      message?: string,
    ): void {
      _assertNotEqualsLimbs(a.fields, b.fields, message);
    }

    static modMul(
      x: ProvableBigint_N,
      y: ProvableBigint_N,
      p: ProvableBigint_N,
    ): ProvableBigint_N {
      const rLimbs = _multiplyLimbs(
        x.fields,
        y.fields,
        p.fields,
        this._NUM_LIMBS,
        this._BIT_SIZE,
        this._LIMBS_TYPE,
        { isSquare: false },
      );
      return new ProvableBigint_N({ fields: rLimbs });
    }

    static modSquare(
      x: ProvableBigint_N,
      p: ProvableBigint_N,
    ): ProvableBigint_N {
      const rLimbs = _multiplyLimbs(
        x.fields,
        x.fields,
        p.fields,
        this._NUM_LIMBS,
        this._BIT_SIZE,
        this._LIMBS_TYPE,
        { isSquare: true },
      );
      return new ProvableBigint_N({ fields: rLimbs });
    }

    checkLimbs(): void {
      _checkLimbs(this.fields, ProvableBigint_N._NUM_LIMBS);
    }

    toBigint(): bigint {
      return _limbsToBigint(this.fields);
    }

    assertEquals(other: ProvableBigint_N, message?: string): void {
      _assertEqualsLimbs(this.fields, other.fields, message);
    }

    assertNotEquals(other: ProvableBigint_N, message?: string): void {
      _assertNotEqualsLimbs(this.fields, other.fields, message);
    }

    modMul(y: ProvableBigint_N, p: ProvableBigint_N): ProvableBigint_N {
      return ProvableBigint_N.modMul(this, y, p);
    }

    /// Does not check fields.
    static fromFields(limbs: Field[]): ProvableBigint_N {
      assert(
        limbs.length === this._NUM_LIMBS,
        `fromFields: Expected ${this._NUM_LIMBS} limbs, got ${limbs.length}`,
      );
      return new ProvableBigint_N({ fields: limbs });
    }
  }

  return ProvableBigint_N;
}

export function rsaExponentiation(
  BigintType: ReturnType<typeof createProvableBigint>,
  signature: InstanceType<typeof BigintType>,
  modulus: InstanceType<typeof BigintType>,
  publicExponent: Field,
  expBitCount: number = EXP_BIT_COUNT,
): InstanceType<typeof BigintType> {
  const one = BigintType.fromBigint(1n);
  const bits = publicExponent.toBits(expBitCount);
  let result = one;

  for (let i = expBitCount - 1; i >= 0; i--) {
    result = BigintType.modSquare(result, modulus);
    let multiplied = BigintType.modMul(result, signature, modulus);
    // Cast the result of Provable.if to the specific Struct type
    result = Provable.if(
      bits[i],
      BigintType,
      multiplied,
      result,
    ) as InstanceType<typeof BigintType>;
  }
  return result;
}
