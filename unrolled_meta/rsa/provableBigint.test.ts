import { describe, it, expect } from "bun:test";
import { Field, Provable, Bool } from "o1js";
import { createProvableBigint, rsaExponentiation } from "./provableBigint"; // Adjust path if needed

// --- Constants from provableBigint.ts ---
const LIMB_BIT_SIZE = 116n;
const LIMB_MAX_VALUE = (1n << LIMB_BIT_SIZE) - 1n;

// --- Helper: RSA Parameter Generation (Simplified for Testing) ---
// Generates p, q, N, phi, e, d that fit within `bitSize`. VERY INSECURE.
function generateSimpleRsaParams(targetNBitSize: number): {
  N: bigint;
  e: bigint;
  d: bigint;
} {
  // Aim for primes roughly half the target N bit size
  const primeBits = Math.floor(targetNBitSize / 2);
  if (primeBits < 10)
    throw new Error("Target N bit size too small for simple param generation");
  console.log(
    `Generating primes around ${primeBits} bits for N ~${targetNBitSize} bits...`,
  );

  // Very basic probable prime generation (not robust)
  const findPrime = (bits: number): bigint => {
    let attempts = 0;
    while (attempts < 1000) {
      // Add attempt limit
      attempts++;
      // Generate random number of 'bits' length
      let candidate = 0n;
      // Simple way to get a random BigInt of approximately bits length
      for (let i = 0; i < bits; i++) {
        if (Math.random() > 0.5) {
          candidate |= 1n << BigInt(i);
        }
      }
      // Ensure it has the top bit set and is odd
      candidate |= 1n << BigInt(bits - 1);
      candidate |= 1n;

      // Simple Miller-Rabin-like check (very few iterations)
      let isPrime = true;
      for (let i = 0; i < 5; ++i) {
        // Low iteration count for speed
        let a = 2n + BigInt(Math.floor(Math.random() * Number(candidate - 3n)));
        if (a <= 1n || a >= candidate) a = 2n; // Basic check for 'a'
        if (powMod(a, candidate - 1n, candidate) !== 1n) {
          isPrime = false;
          break;
        }
      }
      if (isPrime) return candidate;
    }
    throw new Error(
      `Failed to find prime near ${bits} bits after ${attempts} attempts.`,
    );
  };
  // Standard modular exponentiation (using JS BigInt)
  const powMod = (base: bigint, exp: bigint, mod: bigint): bigint => {
    if (mod === 0n) throw new Error("Modulo cannot be zero");
    if (mod === 1n) return 0n;
    let result = 1n;
    base %= mod;
    while (exp > 0n) {
      if (exp % 2n === 1n) result = (result * base) % mod;
      base = (base * base) % mod;
      exp /= 2n;
    }
    return result;
  };
  // Modular inverse (needed for d)
  const modInverse = (a: bigint, m: bigint): bigint => {
    if (m === 1n) return 0n;
    const egcd = (a: bigint, b: bigint): [bigint, bigint, bigint] => {
      if (a === 0n) return [b, 0n, 1n];
      const [g, x1, y1] = egcd(b % a, a);
      const x = y1 - (b / a) * x1;
      const y = x1;
      return [g, x, y];
    };
    let [g, x] = egcd(a, m);
    if (g !== 1n) throw new Error("Modular inverse does not exist");
    return ((x % m) + m) % m; // Ensure result is positive
  };

  let p = 0n,
    q = 0n,
    N = 0n,
    phi = 0n;
  const e = 65537n;
  let d = 0n;
  let success = false;
  let generationAttempts = 0;

  while (!success && generationAttempts < 10) {
    // Limit generation attempts
    generationAttempts++;
    try {
      p = findPrime(primeBits);
      q = findPrime(primeBits);
      if (p === q) continue; // Ensure p != q

      N = p * q;
      phi = (p - 1n) * (q - 1n);

      if (e >= phi) continue; // Ensure e < phi
      // Basic GCD check
      const gcd = (a: bigint, b: bigint): bigint => (!b ? a : gcd(b, a % b));
      if (gcd(e, phi) !== 1n) continue; // Ensure e is coprime to phi

      d = modInverse(e, phi);
      success = true; // Found valid parameters

      // Verify N is roughly the correct size
      const actualNBitSize = N.toString(2).length;
      console.log(
        `Generated params attempt ${generationAttempts}: p=${p.toString().length}d q=${q.toString().length}d => N=${actualNBitSize}b (target ~${targetNBitSize}b)`,
      );
      if (
        actualNBitSize < targetNBitSize * 0.8 ||
        actualNBitSize > targetNBitSize * 1.2
      ) {
        console.warn(
          `Warning: Generated N size (${actualNBitSize} bits) is far from target (${targetNBitSize} bits). Retrying...`,
        );
        success = false; // Retry if size is too different
      }
    } catch (error) {
      console.warn(
        `Parameter generation attempt ${generationAttempts} failed: ${error}`,
      );
    }
  }

  if (!success) {
    throw new Error(
      `Failed to generate suitable RSA parameters for target N size ${targetNBitSize} after multiple attempts.`,
    );
  }

  console.log(
    `Generated params (N ~${N.toString(2).length} bits): N=${N.toString().slice(0, 10)}..., e=${e}, d=${d.toString().slice(0, 10)}...`,
  );
  return { N, e, d };
}

// --- Test Suite Generator ---
function generateTestSuite(bitSize: number) {
  describe(`ProvableBigint${bitSize} Core Functionality`, () => {
    const ProvableBigintN = createProvableBigint(bitSize);
    // NO explicit InstanceType alias needed here

    // --- Conversion Tests ---
    describe("Conversion (fromBigint/toBigint)", () => {
      // ... (testValues remain the same) ...
      const testValues: bigint[] = [
        0n,
        1n,
        123n,
        LIMB_MAX_VALUE,
        LIMB_MAX_VALUE + 5n,
        (1n << (LIMB_BIT_SIZE * BigInt(ProvableBigintN._NUM_LIMBS / 2))) + 1n,
        (1n << BigInt(bitSize - 2)) - 1n,
        (1n << BigInt(bitSize)) - 1n - 12345n,
      ];

      testValues.forEach((b) => {
        if (b >= 1n << BigInt(bitSize)) return; // Skip if too large

        it(`should correctly roundtrip ${b > 1000 ? b.toString().slice(0, 10) + "..." : b}`, async () => {
          await Provable.runAndCheck(() => {
            const pb = ProvableBigintN.fromBigint(b);
            const roundtripBigint = pb.toBigint();
            const roundtripField = Provable.witness(
              Field,
              () => roundtripBigint,
            );
            pb.checkLimbs();
            roundtripField.assertEquals(
              Field(b),
              `Conversion roundtrip failed for ${b}`,
            );
          });
        });
      });

      it(`should throw for value >= 2^${bitSize}`, () => {
        const tooLarge = 1n << BigInt(bitSize);
        const maxAllowed = tooLarge - 1n;
        expect(() => ProvableBigintN.fromBigint(tooLarge)).toThrow(
          new RegExp( // Use RegExp to match the dynamic message
            `Input bigint ${tooLarge} is too large for ${bitSize} bits \\(max is ${maxAllowed}\\)`,
          ),
        );
      });

      it(`should throw for negative value`, () => {
        const negative = -5n;
        expect(() => ProvableBigintN.fromBigint(negative)).toThrow(
          new RegExp(`Input bigint ${negative} must be non-negative`),
        );
      });
    });

    // --- Modular Multiplication Tests ---
    describe("Modular Multiplication (multiply)", () => {
      const testCasesInput: [bigint, bigint, bigint][] = [
        [3n, 5n, 7n],
        [0n, 10n, 13n],
        [1n, 10n, 13n],
        [8n, 9n, 11n],
        [LIMB_MAX_VALUE + 2n, 3n, LIMB_MAX_VALUE + 10n],
        [
          (1n << BigInt(bitSize / 2)) + 5n,
          (1n << BigInt(bitSize / 2)) + 10n,
          (1n << BigInt(bitSize)) - 5n,
        ],
        [
          (1n << BigInt(bitSize / 2)) + 5n,
          (1n << BigInt(bitSize / 2)) + 10n,
          101n,
        ],
      ];
      // Filter AND assert type
      const testCases = testCasesInput.filter(([x, y, p]) => {
        const maxVal = 1n << BigInt(bitSize);
        return x < maxVal && y < maxVal && p < maxVal && p > 0n;
      }) as [bigint, bigint, bigint][]; // <-- Type assertion here

      testCases.forEach(([x, y, p]) => {
        if (p === 0n) return;
        const expected = (x * y) % p;
        it(`should calculate (${x} * ${y}) mod ${p} = ${expected}`, async () => {
          await Provable.runAndCheck(() => {
            const x_pb = ProvableBigintN.fromBigint(x);
            const y_pb = ProvableBigintN.fromBigint(y);
            const p_pb = ProvableBigintN.fromBigint(p);
            const expected_pb = ProvableBigintN.fromBigint(expected);

            x_pb.checkLimbs();
            y_pb.checkLimbs();
            p_pb.checkLimbs();

            // Call multiply without explicit instance type generic
            const result_pb = ProvableBigintN.modMul(x_pb, y_pb, p_pb);

            result_pb.checkLimbs();
            result_pb.assertEquals(
              expected_pb,
              `Modular multiplication mismatch: (${x} * ${y}) mod ${p}`,
            );
          });
        });
      });

      it("should throw error inside witness if modulus p is zero", async () => {
        expect(
          Provable.runAndCheck(() => {
            const x_pb = ProvableBigintN.fromBigint(10n);
            const y_pb = ProvableBigintN.fromBigint(20n);
            const p_pb = ProvableBigintN.fromBigint(0n);
            ProvableBigintN.modMul(x_pb, y_pb, p_pb);
          }),
        ).rejects.toThrow(
          "_multiplyLimbs: Modulus (p) cannot be zero in witness generation",
        );
      });
    });

    // --- Modular Square Tests ---
    describe("Modular Square (modSquare)", () => {
      const testCasesInput: [bigint, bigint][] = [
        [3n, 7n],
        [0n, 13n],
        [1n, 13n],
        [4n, 11n],
        [LIMB_MAX_VALUE + 2n, LIMB_MAX_VALUE + 10n],
        [(1n << BigInt(bitSize / 2)) + 5n, (1n << BigInt(bitSize)) - 5n],
        [(1n << BigInt(bitSize / 2)) + 5n, 101n],
      ];
      // Filter AND assert type
      const testCases = testCasesInput.filter(([x, p]) => {
        const maxVal = 1n << BigInt(bitSize);
        return x < maxVal && p < maxVal && p > 0n;
      }) as [bigint, bigint][]; // <-- Type assertion here

      testCases.forEach(([x, p]) => {
        if (p === 0n) return;
        const expected = (x * x) % p;
        it(`should calculate (${x}^2) mod ${p} = ${expected}`, async () => {
          await Provable.runAndCheck(() => {
            const x_pb = ProvableBigintN.fromBigint(x);
            const p_pb = ProvableBigintN.fromBigint(p);
            const expected_pb = ProvableBigintN.fromBigint(expected);

            x_pb.checkLimbs();
            p_pb.checkLimbs();

            const result_pb = ProvableBigintN.modSquare(x_pb, p_pb);

            result_pb.checkLimbs();
            result_pb.assertEquals(
              expected_pb,
              `Modular square mismatch: (${x}^2) mod ${p}`,
            );
          });
        });
      });
    });

    // --- RSA Circular Property Test ---
    describe("RSA Circular Property (Integration)", () => {
      // Limit practical generation size for speed, especially for 4096 test
      const practicalBitSizeForGeneration = Math.min(bitSize, 512);
      console.log(
        `Generating RSA params for testing ${bitSize}-bit ProvableBigint (using ~${practicalBitSizeForGeneration}-bit N)...`,
      );
      const { N, e, d } =
        bitSize <= 64 // Use tiny params for very small tests if needed
          ? { N: 77n, e: 7n, d: 43n } // Small known params
          : generateSimpleRsaParams(practicalBitSizeForGeneration);

      const m = N > 1 ? (123456789n % (N - 1n)) + 1n : 0n; // Ensure message 0 < m < N

      it(`should verify (m^e)^d mod N = m for (pseudo) ${bitSize}-bit params`, async () => {
        const maxVal = 1n << BigInt(bitSize);
        // Check N and m fit in ProvableBigintN
        if (N >= maxVal || m >= maxVal) {
          console.warn(
            `Skipping RSA test for ${bitSize} bits: Generated N=${N} or m=${m} too large for ProvableBigint.`,
          );
          return; // Test invalid if N or m don't fit
        }
        // Check e and d fit in Field
        if (e >= Field.ORDER || d >= Field.ORDER) {
          console.warn(
            `Skipping RSA test for ${bitSize} bits: Exponents e=${e} or d=${d} too large for Field.`,
          );
          return;
        }
        if (N === 0n) {
          console.warn(
            `Skipping RSA test for ${bitSize} bits: Modulus N is zero.`,
          );
          return;
        }

        // Use fewer bits for exponentiation if exponents are small, max out at bitSize
        const expBitCount = Math.min(
          bitSize,
          Math.max(e.toString(2).length, d.toString(2).length, 64),
        ); // Use sufficient bits, cap at bitSize
        console.log(
          `Using expBitCount = ${expBitCount} for ${bitSize}-bit RSA test.`,
        );

        await Provable.runAndCheck(() => {
          const N_pb = ProvableBigintN.fromBigint(N);
          const m_pb = ProvableBigintN.fromBigint(m);
          const e_field = Field(e);
          const d_field = Field(d);

          m_pb.checkLimbs();
          N_pb.checkLimbs();

          // --- Calculate c = m^e mod N ---
          let c_pb = ProvableBigintN.fromBigint(1n);
          let currentPower_e = m_pb;
          const e_bits = e_field.toBits(expBitCount);

          for (let i = 0; i < expBitCount; i++) {
            const multiplyFlag = e_bits[i];
            let multiplied = ProvableBigintN.modMul(c_pb, currentPower_e, N_pb);
            // Pass ProvableBigintN as the type to Provable.if
            // @ts-ignore
            c_pb = Provable.if(multiplyFlag, ProvableBigintN, multiplied, c_pb);
            currentPower_e = ProvableBigintN.modSquare(currentPower_e, N_pb);
          }
          c_pb.checkLimbs();

          // --- Calculate m_prime = c^d mod N ---
          let m_prime_pb = ProvableBigintN.fromBigint(1n);
          let currentPower_d = c_pb;
          const d_bits = d_field.toBits(expBitCount);

          for (let i = 0; i < expBitCount; i++) {
            const multiplyFlag = d_bits[i];
            let multiplied = ProvableBigintN.modMul(
              m_prime_pb,
              currentPower_d,
              N_pb,
            );
            // @ts-ignore
            m_prime_pb = Provable.if(
              multiplyFlag,
              ProvableBigintN,
              multiplied,
              m_prime_pb,
            );
            currentPower_d = ProvableBigintN.modSquare(currentPower_d, N_pb);
          }
          m_prime_pb.checkLimbs();

          m_prime_pb.assertEquals(
            m_pb,
            `RSA circular property failed (${bitSize} bits)`,
          );
        });
      }, 600000); // Keep increased timeout
    });

    describe("RSA Verification (rsaVerify function)", () => {
      // Use the same params as the Circular Property test or generate new ones
      const practicalBitSizeForGeneration = Math.min(bitSize, 512);
      const { N, e, d } =
        bitSize <= 64
          ? { N: 77n, e: 7n, d: 43n }
          : generateSimpleRsaParams(practicalBitSizeForGeneration);

      const m = N > 1 ? (987654321n % (N - 1n)) + 1n : 0n; // Different message

      it(`should verify a valid signature using rsaVerify for ${bitSize}-bit params`, async () => {
        const maxVal = 1n << BigInt(bitSize);
        if (N >= maxVal || m >= maxVal || e >= Field.ORDER || N === 0n) {
          console.warn(
            `Skipping rsaVerify test for ${bitSize} bits: Params out of range.`,
          );
          return;
        }

        // Calculate signature s = m^d mod N (outside the circuit using BigInt)
        const powMod = (base: bigint, exp: bigint, mod: bigint): bigint => {
          if (mod === 0n) throw new Error("Modulo cannot be zero");
          if (mod === 1n) return 0n;
          let result = 1n;
          base %= mod;
          while (exp > 0n) {
            if (exp % 2n === 1n) result = (result * base) % mod;
            base = (base * base) % mod;
            exp /= 2n;
          }
          return result;
        };
        const s = powMod(m, d, N);
        if (s >= maxVal) {
          console.warn(
            `Skipping rsaVerify test for ${bitSize} bits: Signature 's' too large.`,
          );
          return;
        }

        const expBitCount = Math.min(
          bitSize,
          Math.max(e.toString(2).length, 64),
        );
        console.log(
          `Using expBitCount = ${expBitCount} for ${bitSize}-bit rsaVerify test.`,
        );

        await Provable.runAndCheck(() => {
          const N_pb = ProvableBigintN.fromBigint(N);
          const m_pb = ProvableBigintN.fromBigint(m);
          const s_pb = ProvableBigintN.fromBigint(s);
          const e_field = Field(e);

          m_pb.checkLimbs();
          s_pb.checkLimbs();
          N_pb.checkLimbs();

          // Call the function under test
          const calculated_m_pb = rsaExponentiation(
            ProvableBigintN,
            s_pb,
            N_pb,
            e_field,
            expBitCount,
          );
          calculated_m_pb.assertEquals(
            m_pb,
            "RSA signature verification failed",
          );
        });
      }, 600000); // Timeout needed

      it(`should fail to verify an invalid signature using rsaVerify`, async () => {
        // Similar setup as above...
        const maxVal = 1n << BigInt(bitSize);
        if (
          N >= maxVal ||
          m >= maxVal ||
          e >= Field.ORDER ||
          N === 0n ||
          m + 1n >= maxVal
        ) {
          console.warn(
            `Skipping rsaVerify fail test for ${bitSize} bits: Params out of range.`,
          );
          return;
        }
        // Use an invalid signature (e.g., s+1 or just a different value)
        const s_invalid = m + 1n; // Simple invalid signature for testing
        if (s_invalid >= maxVal) {
          console.warn(
            `Skipping rsaVerify fail test for ${bitSize} bits: Invalid signature too large.`,
          );
          return;
        }

        const expBitCount = Math.min(
          bitSize,
          Math.max(e.toString(2).length, 64),
        );

        // Expect runAndCheck to throw because of the final assertEquals
        expect(
          Provable.runAndCheck(() => {
            const N_pb = ProvableBigintN.fromBigint(N);
            const m_pb = ProvableBigintN.fromBigint(m);
            const s_invalid_pb = ProvableBigintN.fromBigint(s_invalid);
            const e_field = Field(e);

            m_pb.checkLimbs();
            s_invalid_pb.checkLimbs();
            N_pb.checkLimbs();

            const calculated_m_pb = rsaExponentiation(
              ProvableBigintN,
              s_invalid_pb,
              N_pb,
              e_field,
              expBitCount,
            );
            calculated_m_pb.assertEquals(
              m_pb,
              "RSA signature verification failed",
            );
          }),
        ).rejects.toThrow(
          /RSA signature verification failed|Constraint unsatisfied/,
        ); // Check for expected error
      }, 600000);
    });

    describe("Modular Multiplication Edge Cases", () => {
      it("should handle modulus p = 1", async () => {
        await Provable.runAndCheck(() => {
          const x = ProvableBigintN.fromBigint(123n);
          const y = ProvableBigintN.fromBigint(456n);
          const p = ProvableBigintN.fromBigint(1n);
          const expected = ProvableBigintN.fromBigint(0n);
          const result = ProvableBigintN.modMul(x, y, p);
          result.assertEquals(expected);
        });
      });

      it("should handle x = p", async () => {
        const pVal = 101n; // Must be < 2^bitSize
        if (pVal >= 1n << BigInt(bitSize)) return;
        await Provable.runAndCheck(() => {
          const x = ProvableBigintN.fromBigint(pVal);
          const y = ProvableBigintN.fromBigint(5n);
          const p = ProvableBigintN.fromBigint(pVal);
          const expected = ProvableBigintN.fromBigint(0n);
          const result = ProvableBigintN.modMul(x, y, p);
          result.assertEquals(expected);
        });
      });

      it("should handle x = p-1 (square)", async () => {
        const pVal = 101n; // Must be < 2^bitSize
        if (pVal >= 1n << BigInt(bitSize)) return;
        await Provable.runAndCheck(() => {
          const x = ProvableBigintN.fromBigint(pVal - 1n);
          const p = ProvableBigintN.fromBigint(pVal);
          const expected = ProvableBigintN.fromBigint(1n);
          const result = ProvableBigintN.modSquare(x, p);
          result.assertEquals(expected);
        });
      });
    });

    describe("Constraint Enforcement", () => {
      it("should fail checkLimbs for out-of-range limb", async () => {
        const badLimb = Field(1n << LIMB_BIT_SIZE); // Value too large
        const validLimb = Field(1n);
        const numLimbs = ProvableBigintN._NUM_LIMBS;
        if (numLimbs < 1) return; // Should not happen

        const limbs = Array(numLimbs).fill(validLimb);
        limbs[0] = badLimb; // Put bad limb at the start

        expect(
          Provable.runAndCheck(() => {
            // Manually create instance (bypass fromBigint) - need raw value
            const structValue = { fields: limbs };
            const instance = new (ProvableBigintN as any)(structValue); // Use 'as any' carefully for testing internal state
            instance.checkLimbs(); // This should fail the range check
          }),
        ).rejects.toThrow(/Constraint unsatisfied/); // Or a more specific error if possible
      });

      it("should fail ProvableBigintN.check for out-of-range limb", async () => {
        // Similar setup as above
        const badLimb = Field(1n << LIMB_BIT_SIZE);
        const validLimb = Field(1n);
        const numLimbs = ProvableBigintN._NUM_LIMBS;
        if (numLimbs < 1) return;
        const limbs = Array(numLimbs).fill(validLimb);
        limbs[0] = badLimb;

        expect(
          Provable.runAndCheck(() => {
            const bn = ProvableBigintN.fromFields(limbs);
            bn.checkLimbs();
          }),
        ).rejects.toThrow(/Constraint unsatisfied/);
      });
    });

    describe("Assertion Method", () => {
      it("assertEquals should pass for equal values", async () => {
        const val = 12345n;
        if (val >= 1n << BigInt(bitSize)) return;
        await Provable.runAndCheck(() => {
          const pb1 = ProvableBigintN.fromBigint(val);
          const pb2 = ProvableBigintN.fromBigint(val);
          pb1.assertEquals(pb2); // Should pass
        });
      });

      it("assertEquals should fail for different values", async () => {
        const val1 = 12345n;
        const val2 = 54321n;
        if (val1 >= 1n << BigInt(bitSize) || val2 >= 1n << BigInt(bitSize))
          return;
        expect(
          Provable.runAndCheck(() => {
            const pb1 = ProvableBigintN.fromBigint(val1);
            const pb2 = ProvableBigintN.fromBigint(val2);
            pb1.assertEquals(pb2, "Test failure message"); // Should fail
          }),
        ).rejects.toThrow(/Test failure message|Constraint unsatisfied/);
      });
    });
  });
}

// --- Generate and Run Test Suites ---
generateTestSuite(2048);
generateTestSuite(4096);
