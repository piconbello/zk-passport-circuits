import { expect, test, describe } from "bun:test";
import { Bool, Field, Poseidon } from "o1js";
import { createMerkleTreeClass } from "../unrolled/merkle";
import { StaticArray } from "@egemengol/mina-credentials";

describe("Merkle Tree Implementation", () => {
  test("should create a tree with correct root for two elements", () => {
    // Create two sample leaf elements
    const leaf1 = Field(123);
    const leaf2 = Field(456);

    // Calculate expected root manually
    const expectedRoot = Poseidon.hash([leaf1, leaf2]);

    // Create tree with two elements
    const MerkleTree = createMerkleTreeClass(2);
    const tree = new MerkleTree([leaf1, leaf2]);

    // Check if the root matches our expected calculation
    expect(tree.root.toString()).toBe(expectedRoot.toString());
  });

  test("should create a tree with correct root for four elements", () => {
    // Create four sample leaf elements
    const leaf1 = Field(100);
    const leaf2 = Field(200);
    const leaf3 = Field(300);
    const leaf4 = Field(400);

    // Calculate expected root manually
    const hash1 = Poseidon.hash([leaf1, leaf2]);
    const hash2 = Poseidon.hash([leaf3, leaf4]);
    const expectedRoot = Poseidon.hash([hash1, hash2]);

    // Create tree with four elements
    const MerkleTree = createMerkleTreeClass(4);
    const tree = new MerkleTree([leaf1, leaf2, leaf3, leaf4]);

    // Check if the root matches our expected calculation
    expect(tree.root.toString()).toBe(expectedRoot.toString());
  });

  test("should generate valid witness for element at index 0", () => {
    // Create sample elements
    const elements = [Field(111), Field(222), Field(333), Field(444)];

    // Create the tree
    const MerkleTree = createMerkleTreeClass(elements.length);
    const tree = new MerkleTree(elements);

    // Get a witness for the first element
    const witness = tree.getWitness(0);

    // Compute the root using the witness
    const computedRoot = witness.computeRoot(elements[0]);

    // Check that the computed root matches the actual root
    expect(computedRoot.toString()).toBe(tree.root.toString());
  });

  test("should generate valid witness for element at index 1", () => {
    // Create sample elements
    const elements = [Field(111), Field(222), Field(333), Field(444)];

    // Create the tree
    const MerkleTree = createMerkleTreeClass(elements.length);
    const tree = new MerkleTree(elements);

    // Get a witness for the second element
    const witness = tree.getWitness(1);

    // Compute the root using the witness
    const computedRoot = witness.computeRoot(elements[1]);

    // Check that the computed root matches the actual root
    expect(computedRoot.toString()).toBe(tree.root.toString());
  });

  test("should throw error when requesting witness for out-of-bounds index", () => {
    // Create sample elements
    const elements = [Field(111), Field(222)];

    // Create the tree
    const MerkleTree = createMerkleTreeClass(elements.length);
    const tree = new MerkleTree(elements);

    // Check that getting witness for invalid index throws an error
    expect(() => tree.getWitness(-1)).toThrow();
    expect(() => tree.getWitness(2)).toThrow();
  });

  test("should correctly handle tree with padding for non-power-of-2 elements", () => {
    // Create three elements (not a power of 2)
    const elements = [Field(10), Field(20), Field(30)];

    // Create the tree - it should pad to 4 elements internally
    const MerkleTree = createMerkleTreeClass(elements.length);
    const tree = new MerkleTree(elements);

    // Get witnesses for all three elements
    const witness0 = tree.getWitness(0);
    const witness1 = tree.getWitness(1);
    const witness2 = tree.getWitness(2);

    // Verify all witnesses compute the correct root
    expect(witness0.computeRoot(elements[0]).toString()).toBe(
      tree.root.toString(),
    );
    expect(witness1.computeRoot(elements[1]).toString()).toBe(
      tree.root.toString(),
    );
    expect(witness2.computeRoot(elements[2]).toString()).toBe(
      tree.root.toString(),
    );
  });
});

describe("Merkle Tree Extended Tests", () => {
  test("should correctly handle larger trees (8 elements)", () => {
    const elements = Array(8)
      .fill(0)
      .map((_, i) => Field(i * 100 + 1));
    const MerkleTree = createMerkleTreeClass(elements.length);
    const tree = new MerkleTree(elements);

    // Verify each leaf's witness
    for (let i = 0; i < elements.length; i++) {
      const witness = tree.getWitness(i);
      const computedRoot = witness.computeRoot(elements[i]);
      expect(computedRoot.toString()).toBe(tree.root.toString());
    }
  });

  test("should handle edge case with only one element", () => {
    const elements = [Field(999)];
    const MerkleTree = createMerkleTreeClass(elements.length);
    const tree = new MerkleTree(elements);

    const witness = tree.getWitness(0);
    const computedRoot = witness.computeRoot(elements[0]);
    expect(computedRoot.toString()).toBe(tree.root.toString());
  });

  test("should maintain correct tree structure with specific elements", () => {
    const elements = [Field(1), Field(2), Field(3), Field(4)];
    const MerkleTree = createMerkleTreeClass(elements.length);
    const tree = new MerkleTree(elements);

    // Manually calculate the expected structure
    const h12 = Poseidon.hash([elements[0], elements[1]]);
    const h34 = Poseidon.hash([elements[2], elements[3]]);
    const expectedRoot = Poseidon.hash([h12, h34]);

    expect(tree.root.toString()).toBe(expectedRoot.toString());

    // Verify the witness for element at index 2
    const witness2 = tree.getWitness(2);

    // The witness for element 2 should have element 3 as first neighbor
    // and the hash of elements 1 and 2 as second neighbor
    expect(witness2.neighbors.get(0).toString()).toBe(elements[3].toString());
    expect(witness2.isNeigborLefts.get(0).toBoolean()).toBe(false);
    expect(witness2.neighbors.get(1).toString()).toBe(h12.toString());
    expect(witness2.isNeigborLefts.get(1).toBoolean()).toBe(true);
  });

  test("should create different witness paths for each element", () => {
    const elements = [Field(5), Field(10), Field(15), Field(20)];
    const MerkleTree = createMerkleTreeClass(elements.length);
    const tree = new MerkleTree(elements);

    const witness0 = tree.getWitness(0);
    const witness1 = tree.getWitness(1);
    const witness2 = tree.getWitness(2);
    const witness3 = tree.getWitness(3);

    // Check that witnesses are different
    expect(witness0.neighbors.get(0).toString()).not.toBe(
      witness1.neighbors.get(0).toString(),
    );
    expect(witness2.neighbors.get(0).toString()).not.toBe(
      witness3.neighbors.get(0).toString(),
    );

    // Check directionality flag is correct
    expect(witness0.isNeigborLefts.get(0).toBoolean()).toBe(false); // Right sibling
    expect(witness1.isNeigborLefts.get(0).toBoolean()).toBe(true); // Left sibling
    expect(witness2.isNeigborLefts.get(0).toBoolean()).toBe(false); // Right sibling
    expect(witness3.isNeigborLefts.get(0).toBoolean()).toBe(true); // Left sibling
  });

  test("should have consistent behavior when recomputing the same tree", () => {
    const elements = [Field(42), Field(43), Field(44), Field(45)];

    // Create the same tree twice
    const MerkleTree = createMerkleTreeClass(elements.length);
    const tree1 = new MerkleTree(elements);
    const tree2 = new MerkleTree(elements);

    // Roots should match
    expect(tree1.root.toString()).toBe(tree2.root.toString());

    // Witnesses should produce identical paths
    for (let i = 0; i < elements.length; i++) {
      const witness1 = tree1.getWitness(i);
      const witness2 = tree2.getWitness(i);

      for (let j = 0; j < MerkleTree.Witness.height(); j++) {
        expect(witness1.neighbors.get(j).toString()).toBe(
          witness2.neighbors.get(j).toString(),
        );
        expect(witness1.isNeigborLefts.get(j).toBoolean()).toBe(
          witness2.isNeigborLefts.get(j).toBoolean(),
        );
      }
    }
  });

  test("should correctly handle witness for odd number of elements", () => {
    const elements = [Field(1), Field(2), Field(3)];
    const MerkleTree = createMerkleTreeClass(elements.length);
    const tree = new MerkleTree(elements);

    // Check that all witnesses compute to the same root
    for (let i = 0; i < elements.length; i++) {
      const witness = tree.getWitness(i);
      const computedRoot = witness.computeRoot(elements[i]);
      expect(computedRoot.toString()).toBe(tree.root.toString());
    }
  });

  test("should verify proof for modified elements fails", () => {
    const elements = [Field(1), Field(2), Field(3), Field(4)];
    const MerkleTree = createMerkleTreeClass(elements.length);
    const tree = new MerkleTree(elements);

    // Get witness for element at index 1
    const witness = tree.getWitness(1);

    // Try to verify with the wrong element
    const modifiedElement = Field(99);
    const computedRoot = witness.computeRoot(modifiedElement);

    // This should not match the original root
    expect(computedRoot.toString()).not.toBe(tree.root.toString());
  });
});
