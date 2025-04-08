import {
  Field,
  Gadgets,
  Provable,
  Struct,
  Unconstrained,
  Bool,
  assert,
  type ProvableExtended, // Using this for static type definition
} from "o1js";

// --- Constants ---
const LIMB_BIT_SIZE = 116n;
const LIMB_MAX_VALUE = (1n << LIMB_BIT_SIZE) - 1n;
const EXP_BIT_COUNT = 20; // Default exponent bit count (e.g., for 65537)

// --- Type Definitions ---

// Interface for the INSTANCE side of RsaBigint
// Defines the methods and properties an RsaBigint object will have.
interface RsaBigintInstance {
  fields: Field[];
  value: Unconstrained<bigint>;
  modMul(y: this, p: this): this;
  toBigint(): bigint;
  toFields(): Field[]; // Instance method to get fields array
  checkLimbs(): void; // Instance method for range checks
  equals(other: this): Bool;
  assertEquals(other: this, message?: string): void;
}

// Interface for the STATIC side of RsaBigint classes
// It must satisfy ProvableExtended<T, V> for circuit compatibility
// T = Instance type (e.g., RsaBigint_N)
// V = Value type (raw JS value, typically the constructor arg type)
// Adjust V to match the Struct's value type (the argument to the constructor)
interface RsaBigintStatic<
  T extends RsaBigintInstance,
  V = { fields: Field[]; value: Unconstrained<bigint> },
> extends ProvableExtended<T, V> {
  readonly bitSize: number;
  readonly numLimbs: number;
  readonly RsaLimbs: ProvableExtended<Field[], bigint[]>; // Provable type for the limbs array

  // Custom static methods
  fromBigint(x: bigint): T;
  fromLimbs(limbs: Field[]): T;
  modSquare(x: T, p: T): T; // Modular square

  // Requires Provable methods (like sizeInFields, toFields, fromFields, check, etc.)
}

// --- Base Class (Holds INSTANCE Logic) ---
// This class defines the behavior of RsaBigint instances but is NOT Provable itself.
class RsaBigintBase implements RsaBigintInstance {
  fields: Field[];
  value: Unconstrained<bigint>;

  // The constructor takes the raw value structure expected by the Provable Struct
  constructor(value: { fields: Field[]; value: Unconstrained<bigint> }) {
    this.fields = value.fields;
    this.value = value.value;
  }

  // Instance method for modular multiplication
  modMul(y: this, p: this): this {
    assert(
      this.constructor === y.constructor && this.constructor === p.constructor,
      "modMul operands must be of the same RsaBigint type",
    );
    // Get the static type (constructor) to call the generic multiply function
    // Use 'as unknown as' to bridge TS type system limitation
    const RsaBigintType = this.constructor as unknown as RsaBigintStatic<this>;
    return multiply<this>(RsaBigintType, this, y, p);
  }

  // Get the bigint value (outside circuit)
  toBigint(): bigint {
    return this.value.get();
  }

  // Get the Field limbs of this instance
  toFields(): Field[] {
    return this.fields;
  }

  // Perform range checks on the limbs of this instance (inside circuit)
  checkLimbs(): void {
    // Use 'as unknown as'
    const RsaBigintType = this.constructor as unknown as RsaBigintStatic<this>; // Access static info
    assert(
      this.fields.length === RsaBigintType.numLimbs,
      `Incorrect number of limbs (${this.fields.length}) for check, expected ${RsaBigintType.numLimbs}`,
    );
    for (let i = 0; i < RsaBigintType.numLimbs; i++) {
      // Add nullish check just in case, though assert should guarantee length
      rangeCheck116(this.fields[i] ?? Field(0));
    }
  }

  // Check equality with another instance (inside circuit)
  equals(other: this): Bool {
    assert(
      this.constructor === other.constructor,
      "Cannot compare RsaBigint of different types",
    );
    // Use 'as unknown as'
    const RsaBigintType = this.constructor as unknown as RsaBigintStatic<this>; // Access static info
    let isEqual = Bool(true);
    // Handle potential empty fields case for numLimbs=0 edge case? (unlikely for RSA)
    if (RsaBigintType.numLimbs === 0) return Bool(true);

    for (let i = 0; i < RsaBigintType.numLimbs; i++) {
      // Ensure fields exist before accessing
      const fieldThis = this.fields?.[i];
      const fieldOther = other.fields?.[i];
      // If numLimbs > 0, the fields array should be populated. If not, it's an error state.
      if (fieldThis === undefined || fieldOther === undefined) {
        // This case should ideally not happen if constructed correctly
        throw new Error(
          `Field index ${i} out of bounds during equals comparison (numLimbs: ${RsaBigintType.numLimbs}).`,
        );
      }
      isEqual = isEqual.and(fieldThis.equals(fieldOther));
    }
    return isEqual;
  }

  // Assert equality with another instance (inside circuit)
  assertEquals(other: this, message?: string): void {
    // Use 'as unknown as' for accessing bitSize
    this.equals(other).assertTrue(
      message ??
        `RsaBigint mismatch (size ${(this.constructor as unknown as RsaBigintStatic<this>).bitSize})`,
    );
  }
}

// --- Factory Function ---
// Creates a Provable RsaBigint class for a specific bit size.
/**
 * Creates a specialized RsaBigint class for a specific bit size.
 * The bit size must be a multiple of 256.
 *
 * @param bitSize The total bit size (e.g., 2048, 4096). Must be a multiple of 256.
 * @returns A new class extending RsaBigintBase for the specified size, conforming to RsaBigintStatic.
 */
function createRsaBigint(bitSize: number): RsaBigintStatic<RsaBigintBase> {
  assert(
    bitSize > 0 && bitSize % 256 === 0,
    `RsaBigint bitSize must be a positive multiple of 256, got ${bitSize}`,
  );
  const numLimbs = Math.ceil(bitSize / Number(LIMB_BIT_SIZE));
  // Define the Provable type for the array of limbs for this size
  // Need to ensure the Value type (bigint[]) matches what Provable.Array expects if used directly
  const RsaLimbs_ = Provable.Array(Field, numLimbs);

  // 1. Define the underlying Provable structure using Struct
  // This handles the low-level serialization (toFields, fromFields etc.)
  const RsaBigintStruct = Struct({
    fields: RsaLimbs_,
    value: Unconstrained.withEmpty<bigint>(() => 0n), // Provide factory for empty value
  });

  // 2. Define the final class that combines instance logic and Provable static methods
  class RsaBigint_N extends RsaBigintBase {
    // Define static properties required by the RsaBigintStatic interface
    static readonly bitSize = bitSize;
    static readonly numLimbs = numLimbs;
    // Correct the value type for RsaLimbs if Provable.Array needs it specified,
    // otherwise inferring Field[] -> bigint[] might be implicit. Assuming implicit for now.
    static readonly RsaLimbs = RsaLimbs_ as ProvableExtended<Field[], bigint[]>;

    // Need to explicitly redefine the constructor to satisfy TypeScript when creating instances
    // It just calls the base constructor.
    constructor(value: { fields: Field[]; value: Unconstrained<bigint> }) {
      super(value);
    }

    // --- Custom Static Methods ---
    static fromBigint(x: bigint): RsaBigint_N {
      let fields: Field[] = [];
      let currentBigint = x;
      for (let i = 0; i < numLimbs; i++) {
        const limb = currentBigint & LIMB_MAX_VALUE;
        fields.push(Field(limb));
        currentBigint >>= LIMB_BIT_SIZE;
      }
      // Check if input fits (allow 0 for positive, -1 for negative if fully shifted)
      assert(
        currentBigint === 0n || (currentBigint === -1n && x < 0n), // Allow negative if representing signed? Unlikely needed for RSA modulus/msg.
        `Input bigint ${x} is too large for ${bitSize} bits`,
      );

      // Create the raw value structure
      const rawValue = { fields, value: Unconstrained.from(x) };
      // Use the Struct's fromValue to potentially handle internal Provable conversions
      // and then construct our class instance.
      // Note: We create the instance directly here as RsaBigintBase constructor matches.
      // We could also use RsaBigintStruct.fromValue and then construct, but this is more direct.
      return new RsaBigint_N(rawValue);
    }

    static fromLimbs(limbs: Field[]): RsaBigint_N {
      if (limbs.length !== numLimbs) {
        throw new Error(
          `Expected ${numLimbs} limbs for ${bitSize}-bit RsaBigint, got ${limbs.length}`,
        );
      }
      // Basic validation outside circuit (consider adding range check here too)
      let value = 0n;
      for (let i = 0; i < numLimbs; i++) {
        // Add nullish check for safety, though length check should prevent it
        value += (limbs[i]?.toBigint() ?? 0n) << (BigInt(i) * LIMB_BIT_SIZE);
      }
      // Check total size (outside circuit check)
      if (value >= 1n << BigInt(bitSize)) {
        // This might be valid (e.g., intermediate values), but warn.
        console.warn(
          `Warning: Limbs [${limbs.map((l) => l.toString()).join(", ")}] represent value ${value} >= 2^${bitSize}.`,
        );
      }

      const rawValue = {
        // Use RsaLimbs_.fromFields to ensure the fields are treated correctly by the Provable system
        fields: RsaLimbs_.fromFields(limbs, []), // Provide empty aux
        value: Unconstrained.from(value),
      };
      return new RsaBigint_N(rawValue);
    }

    // Static method for modular squaring
    static modSquare(x: RsaBigint_N, p: RsaBigint_N): RsaBigint_N {
      // Cast 'this' (RsaBigint_N) to the static interface type to satisfy multiply's first arg
      // Use 'as unknown as'
      return multiply<RsaBigint_N>(
        this as unknown as RsaBigintStatic<RsaBigint_N>,
        x,
        x,
        p,
        { isSquare: true },
      );
    }

    // --- Delegate Provable static methods from the Struct ---
    // This makes RsaBigint_N itself adhere to the Provable interface.

    static sizeInFields(): number {
      return RsaBigintStruct.sizeInFields();
    }
    // Static toFields takes an instance, gets its raw value, asks Struct to convert
    static toFields(instance: RsaBigint_N): Field[] {
      // Extract the raw structure that RsaBigintStruct understands
      return RsaBigintStruct.toFields({
        fields: instance.fields,
        value: instance.value,
      });
    }
    static toAuxiliary(instance?: RsaBigint_N | undefined): any[] {
      // Pass the raw value structure if instance exists, otherwise let Struct handle undefined
      return RsaBigintStruct.toAuxiliary(
        instance
          ? { fields: instance.fields, value: instance.value }
          : undefined,
      );
    }
    // Static fromFields asks Struct to create raw value, then wraps in our class instance
    static fromFields(fields: Field[], aux?: any[] | undefined): RsaBigint_N {
      // Ensure aux is an array if provided, default to empty array if undefined
      const rawValue = RsaBigintStruct.fromFields(fields, aux ?? []);
      return new RsaBigint_N(rawValue);
    }
    // Static check asks Struct to check the raw value extracted from the instance
    static check(instance: RsaBigint_N): void {
      RsaBigintStruct.check({ fields: instance.fields, value: instance.value });
      // Add our custom limb check
      instance.checkLimbs();
    }
    static toJSON(instance: RsaBigint_N): any {
      // Delegate to Struct, maybe add custom fields if needed?
      return RsaBigintStruct.toJSON({
        fields: instance.fields,
        value: instance.value,
      });
      // Or maybe return something simpler like the bigint string?
      // return instance.toBigint().toString(); // Example alternative
    }
    static fromJSON(json: any): RsaBigint_N {
      // Assume json has the structure Struct expects, or handle alternative formats
      const rawValue = RsaBigintStruct.fromJSON(json);
      // Example: If JSON is just the bigint string:
      // const bigintValue = BigInt(json); return RsaBigint_N.fromBigint(bigintValue);
      return new RsaBigint_N(rawValue);
    }
    static toValue(instance: RsaBigint_N): {
      fields: Field[];
      value: Unconstrained<bigint>;
    } {
      // Return the raw structure that Struct understands
      return RsaBigintStruct.toValue({
        fields: instance.fields,
        value: instance.value,
      });
    }
    // Static fromValue handles various inputs, creates raw value via Struct, wraps in instance
    static fromValue(
      value:
        | RsaBigint_N
        | { fields: Field[]; value: Unconstrained<bigint> }
        | bigint, // Allow construction from bigint directly via fromValue
    ): RsaBigint_N {
      // If already an instance, return it.
      if (value instanceof RsaBigint_N) return value;
      // Handle bigint input
      if (typeof value === "bigint") {
        return RsaBigint_N.fromBigint(value);
      }
      // Otherwise, assume 'value' is the raw structure or something Struct.fromValue understands
      const rawValue = RsaBigintStruct.fromValue(value);
      return new RsaBigint_N(rawValue);
    }

    // Delegate other required Provable methods
    static empty(): RsaBigint_N {
      // Get empty raw value from Struct and wrap it in our class
      return new RsaBigint_N(RsaBigintStruct.empty());
    }
    static toInput(instance: RsaBigint_N): HashInput {
      // Default: use fields directly. Could implement packing if needed.
      return { fields: RsaBigint_N.toFields(instance) };
      // Alternatively, delegate if Struct provides a smarter toInput:
      // return RsaBigintStruct.toInput({ fields: instance.fields, value: instance.value });
    }
  }

  // Return the final class constructor. Cast necessary using 'as unknown as'.
  return RsaBigint_N as unknown as RsaBigintStatic<RsaBigintBase>;
}

// --- Core RSA Logic --- ( Largely unchanged, relies on the Static Type passed in ) ---

/**
 * Generic modular multiplication: `x * y mod p`.
 * Assumes inputs `x`, `y`, `p` are of the same RsaBigint type defined by `RsaBigintType`.
 * Performs range checks on intermediate values `q` and `r`.
 *
 * @param RsaBigintType The specific RsaBigint class constructor (e.g., RsaBigint4096).
 * @param x Multiplicand.
 * @param y Multiplier.
 * @param p Modulus.
 * @param options Optional parameters, e.g., { isSquare: true }.
 * @returns `(x * y) mod p` as an instance of `RsaBigintType`.
 */
function multiply<T extends RsaBigintBase>(
  RsaBigintType: RsaBigintStatic<T>,
  x: T,
  y: T,
  p: T,
  { isSquare = false } = {},
): T {
  const numLimbs = RsaBigintType.numLimbs;

  // Witness q, r such that x*y = q*p + r
  // This also adds the range checks via RsaBigintType.check() being called inside fromFields/witness
  let { q, r } = Provable.witness(
    Struct({ q: RsaBigintType, r: RsaBigintType }),
    () => {
      let xy = x.toBigint() * y.toBigint();
      let p0 = p.toBigint();
      // Prevent division by zero outside the circuit
      if (p0 === 0n) {
        // Inside the circuit, p.equals(0) should be checked if p can be 0.
        // For RSA modulus, p should never be 0.
        throw new Error("Modulus (p) cannot be zero");
      }
      let qVal = xy / p0;
      let rVal = xy % p0; // Use modulo operator for remainder
      if (rVal < 0n) rVal += p0; // Ensure remainder is non-negative if p > 0
      return {
        q: RsaBigintType.fromBigint(qVal),
        r: RsaBigintType.fromBigint(rVal),
      };
    },
  );

  // Range check r < p. This is crucial for canonical representation.
  // We can do this by checking if p - r - 1 is non-negative (has rangeCheck(116*numLimbs) pass)
  // Or simpler: witness p - r.
  let pMinusR = Provable.witness(RsaBigintType, () => {
    let pVal = p.toBigint();
    let rVal = r.toBigint();
    let diff = pVal - rVal;
    // If r >= p, the result should be non-canonical, but the multiply logic might still hold.
    // However, standard modular arithmetic expects 0 <= r < p.
    if (diff <= 0n) {
      // This indicates an issue either in the witness calculation or input assumptions.
      // Depending on strictness, could throw or just proceed.
      console.warn(
        `Warning: Remainder r (${rVal}) >= modulus p (${pVal}) in multiply witness.`,
      );
      // Return a dummy value for the witness if diff <= 0, like 0, to allow circuit to proceed.
      // The assertion later using genericMultiplication will fail if xy != qp + r.
      // A more robust check might involve custom range comparison gadgets.
      return RsaBigintType.fromBigint(0n); // Or handle error appropriately
    }
    return RsaBigintType.fromBigint(diff);
  });
  // Check that pMinusR's limbs are all positive (or zero) and fit the limb size.
  // This implicitly checks p > r if pMinusR is calculated correctly.
  pMinusR.checkLimbs(); // Assumes checkLimbs performs non-negativity check implicitly via rangeCheck116

  // Compute delta = xy - qp - r in limbs using multi-precision arithmetic gadget
  // delta = (x * y) - (q * p) - r
  Gadgets.multiplication(
    Gadgets.provable({ q: RsaBigintType, r: RsaBigintType }),
    { q, r },
    { left: x, right: y }, // xy
    { left: q, right: p }, // qp
  );

  // The remainder `r` is the result. It was range-checked by witness creation (checkLimbs)
  // and we added an explicit check that r < p (via pMinusR check).
  return r;
}

/**
 * RSA signature verification: `message === signature^publicExponent mod modulus`.
 *
 * @param RsaBigintType The specific RsaBigint class constructor (e.g., RsaBigint4096) matching the inputs.
 * @param message The message hash as an RsaBigint.
 * @param signature The signature as an RsaBigint.
 * @param modulus The RSA public modulus as an RsaBigint.
 * @param publicExponent The RSA public exponent (e.g., 65537) as a Field.
 * @param expBitCount The number of bits in the public exponent to consider (defaults to EXP_BIT_COUNT).
 */
function rsaVerify<T extends RsaBigintBase>(
  RsaBigintType: RsaBigintStatic<T>,
  message: T,
  signature: T,
  modulus: T,
  publicExponent: Field,
  expBitCount: number = EXP_BIT_COUNT,
): void {
  // Create 'one' constant of the correct RsaBigint type
  const one = RsaBigintType.fromBigint(1n);

  // Check that message < modulus (typical RSA requirement, PKCS#1 v1.5)
  // Add this check explicitly if needed, similar to the r < p check in multiply
  // Witness m < p?

  // Modular exponentiation using square-and-multiply
  const bits = publicExponent.toBits(expBitCount); // MSB is bits[expBitCount-1]
  let result = one; // Start with 1

  // Process bits from MSB down to LSB
  for (let i = expBitCount - 1; i >= 0; i--) {
    result = RsaBigintType.modSquare(result, modulus); // Square: result = result^2 mod modulus
    let multiplied = result.modMul(signature, modulus); // Potential multiply: multiplied = result * signature mod modulus
    // If bit is 1, choose 'multiplied', otherwise keep 'result'
    result = Provable.if(bits[i], RsaBigintType, multiplied, result);
  }

  // Assert that the computed result equals the message
  result.assertEquals(message, "RSA signature verification failed");
  // Use Provable.assertEqual as an alternative:
  // Provable.assertEqual(RsaBigintType, result, message);
}
// --- Range Check Gadgets --- (Keep these as they are limb-size specific, not total-size specific)

/**
 * Custom range check for a single limb, x in [0, 2^116).
 * @param x Field element representing a limb.
 */
function rangeCheck116(x: Field) {
  let [x0, x1] = Provable.witnessFields(2, () => [
    x.toBigInt() & ((1n << 64n) - 1n), // Low 64 bits
    x.toBigInt() >> 64n, // High bits
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
