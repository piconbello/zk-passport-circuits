import { describe, test, expect, beforeAll } from "bun:test";
import * as merger from "../src/merger";
import { VerificationKey, Field, Poseidon, ZkProgram } from "o1js";
import { Out } from "../circuits/bimodal/common";

function mockVK(hash: Field): VerificationKey {
  return new VerificationKey({
    data: "",
    hash,
  });
}

describe("calculateRootVKDigest", () => {
  test("correctly calculates root digest for 7 elements", () => {
    // Create 7 mock verification keys with simple values
    const vks = [
      mockVK(Field(1)),
      mockVK(Field(2)),
      mockVK(Field(3)),
      mockVK(Field(4)),
      mockVK(Field(5)),
      mockVK(Field(6)),
      mockVK(Field(7)),
    ];

    // Calculate the expected result manually
    // Level 1: Pair hashes
    const hash12 = Poseidon.hash([Field(1), Field(2)]);
    const hash34 = Poseidon.hash([Field(3), Field(4)]);
    const hash56 = Poseidon.hash([Field(5), Field(6)]);
    // Element 7 stays as is at this level

    // Level 2: Further reduction
    const hash1234 = Poseidon.hash([hash12, hash34]);
    const hash567 = Poseidon.hash([hash56, Field(7)]);

    // Level 3: Final root
    const expectedRoot = Poseidon.hash([hash1234, hash567]);

    // Run the function
    const actualRoot = merger.calculateRootVKDigest(vks);

    // Check the result
    expect(actualRoot).toEqual(expectedRoot);
  });

  test("handles single element case", () => {
    const vk = mockVK(Field(42));
    expect(merger.calculateRootVKDigest([vk])).toEqual(Field(42));
  });

  test("handles two elements case", () => {
    const vk1 = mockVK(Field(10));
    const vk2 = mockVK(Field(20));
    const expected = Poseidon.hash([Field(10), Field(20)]);
    expect(merger.calculateRootVKDigest([vk1, vk2])).toEqual(expected);
  });

  test("handles empty array", () => {
    // Define your expected behavior for empty input
    expect(() => merger.calculateRootVKDigest([])).toThrow(
      "Empty array of VerificationKeys",
    );
  });
});

// Create a simple program for testing
const TestLeafProgram1 = ZkProgram({
  name: "test-leaf-1",
  publicOutput: Out,
  methods: {
    generate: {
      privateInputs: [Field, Field],
      async method(left: Field, right: Field) {
        return {
          publicOutput: new Out({
            left,
            right,
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});
const TestLeafProgram2 = ZkProgram({
  name: "test-leaf-2",
  publicOutput: Out,
  methods: {
    generate: {
      privateInputs: [Field, Field],
      async method(left: Field, right: Field) {
        return {
          publicOutput: new Out({
            left,
            right,
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});
const TestLeafProgram3 = ZkProgram({
  name: "test-leaf-3",
  publicOutput: Out,
  methods: {
    generate: {
      privateInputs: [Field, Field],
      async method(left: Field, right: Field) {
        return {
          publicOutput: new Out({
            left,
            right,
            vkDigest: Field(0),
          }),
        };
      },
    },
  },
});

describe("generateRootProof", () => {
  let vk1: VerificationKey;
  let vk2: VerificationKey;
  let vk3: VerificationKey;
  beforeAll(async () => {
    console.log("Starting compilation of merger program...");
    await merger.compile();
    console.log("Merger program compilation completed");

    console.log("Starting compilation of test leaf programs...");
    const { verificationKey: verificationKey1 } =
      await TestLeafProgram1.compile();
    console.log("TestLeafProgram1 compilation completed");

    const { verificationKey: verificationKey2 } =
      await TestLeafProgram2.compile();
    console.log("TestLeafProgram2 compilation completed");

    const { verificationKey: verificationKey3 } =
      await TestLeafProgram3.compile();
    console.log("TestLeafProgram3 compilation completed");

    vk1 = verificationKey1;
    vk2 = verificationKey2;
    vk3 = verificationKey3;
  });
  test("merges three leaf proofs correctly", async () => {
    const vks = [vk1, vk2, vk3];

    // Generate three leaf proofs with consecutive values
    console.log("Generating leaf proofs...");
    const proof1 = await TestLeafProgram1.generate(Field(1), Field(2));
    const proof2 = await TestLeafProgram2.generate(Field(2), Field(3));
    const proof3 = await TestLeafProgram3.generate(Field(3), Field(4));
    console.log("Leaf proofs generated");

    // Generate the root proof by merging
    console.log("Generating root proof...");
    const rootProof = await merger.generateRootProof(
      [proof1.proof, proof2.proof, proof3.proof],
      vks,
    );
    console.log("Root proof generated");

    // Verify the root proof's output
    expect(rootProof.publicOutput.left.toString()).toEqual("1");
    expect(rootProof.publicOutput.right.toString()).toEqual("4");

    expect(merger.calculateRootVKDigest(vks).toString()).toEqual(
      rootProof.publicOutput.vkDigest.toString(),
    );
  }, 100000); // Increase timeout to 100 seconds as proof generation can be slow

  test("handles single proof correctly", async () => {
    // Test with just one proof
    const proof1 = await TestLeafProgram1.generate(Field(5), Field(10));
    const rootProof = await merger.generateRootProof([proof1.proof], [vk1]);

    // Verify the output matches the input
    expect(rootProof.publicOutput.left.toString()).toEqual("5");
    expect(rootProof.publicOutput.right.toString()).toEqual("10");
    expect(rootProof.publicOutput.vkDigest.toString()).toEqual(
      vk1.hash.toString(),
    );
  }, 100000);

  test("handles two proofs correctly", async () => {
    // Test with exactly two proofs
    const proof1 = await TestLeafProgram1.generate(Field(7), Field(8));
    const proof2 = await TestLeafProgram2.generate(Field(8), Field(9));

    const rootProof = await merger.generateRootProof(
      [proof1.proof, proof2.proof],
      [vk1, vk2],
    );

    // Verify proper merging
    expect(rootProof.publicOutput.left.toString()).toEqual("7");
    expect(rootProof.publicOutput.right.toString()).toEqual("9");

    // Verify VK digest matches expected hash
    const expectedVkDigest = Poseidon.hash([vk1.hash, vk2.hash]);
    expect(rootProof.publicOutput.vkDigest.toString()).toEqual(
      expectedVkDigest.toString(),
    );
  }, 100000);

  test("throws error when proof and vk counts don't match", async () => {
    const proof1 = await TestLeafProgram1.generate(Field(1), Field(2));

    // Try to generate with mismatched arrays
    expect(
      merger.generateRootProof([proof1.proof], [vk1, vk2]),
    ).rejects.toThrow(
      "Number of proofs must match number of verification keys",
    );
  }, 100000);
});
