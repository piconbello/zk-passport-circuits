import { expect, test, describe } from "bun:test";
import { Bool, Field, Poseidon, Provable } from "o1js";
import {
  MerkleTree,
  type Step,
  calcMerkleHeightFor,
} from "../unrolled_meta/merkle"; // Adjust path if needed

// Helper function to compute root from a leaf and its witness path (Step[])
function computeRootFromPath(leaf: Field, path: Step[]): Field {
  let currentHash = leaf;
  for (const step of path) {
    // Use the logic similar to MerkleWitnessStep.calculateParentFor
    currentHash = Provable.if(
      step.isNeighborLeft,
      Poseidon.hash([step.neighbor, currentHash]), // Neighbor is on the left
      Poseidon.hash([currentHash, step.neighbor]), // Neighbor is on the right
    );
  }
  return currentHash;
}

describe("Merkle Tree Implementation (unrolled_meta)", () => {
  test("should throw error if initialized with no elements", () => {
    expect(() => new MerkleTree([])).toThrow(
      "MerkleTree must be initialized with at least one element.",
    );
  });

  test("should throw error if initialized with invalid elements", () => {
    expect(() => new MerkleTree([Field(1), null as any])).toThrow(
      "Invalid element at index 1: must be a valid Field",
    );
    expect(() => new MerkleTree([Field(1), undefined as any])).toThrow(
      "Invalid element at index 1: must be a valid Field",
    );
    expect(() => new MerkleTree([Field(1), 123 as any])).toThrow(
      // Not a Field
      "Invalid element at index 1: must be a valid Field",
    );
  });

  test("should create a tree with correct root for one element", () => {
    const elements = [Field(999)];
    const tree = new MerkleTree(elements);

    // For a single element, the root is the element itself after padding (if height > 0)
    // The height will be 0, leafCount 1, treeSize 1. Root is element[0].
    // If implementation padded to height 1: root would be hash(el, 0)
    // Let's check the height calculation and expected root based on the *actual* implementation
    const height = calcMerkleHeightFor(elements.length); // Should be 0
    expect(height).toBe(0);
    expect(tree.height).toBe(0); // Implementation calculates height=0

    // If height is 0, the tree array size is 2*2^0 - 1 = 1.
    // The root is simply the single element.
    expect(tree.root.toString()).toBe(elements[0].toString());

    // Witness for the single element should have height 0 (empty path)
    const path = tree.getWitnessAt(0);
    expect(path.length).toBe(0);
    const computedRoot = computeRootFromPath(elements[0], path);
    expect(computedRoot.toString()).toBe(tree.root.toString());
  });

  test("should create a tree with correct root for two elements", () => {
    // Create two sample leaf elements
    const leaf1 = Field(123);
    const leaf2 = Field(456);
    const elements = [leaf1, leaf2];

    // Calculate expected root manually
    const expectedRoot = Poseidon.hash([leaf1, leaf2]);

    // Create tree with two elements
    const tree = new MerkleTree(elements);

    // Check height
    expect(tree.height).toBe(1);

    // Check if the root matches our expected calculation
    expect(tree.root.toString()).toBe(expectedRoot.toString());
  });

  test("should create a tree with correct root for four elements", () => {
    // Create four sample leaf elements
    const leaf1 = Field(100);
    const leaf2 = Field(200);
    const leaf3 = Field(300);
    const leaf4 = Field(400);
    const elements = [leaf1, leaf2, leaf3, leaf4];

    // Calculate expected root manually
    const hash12 = Poseidon.hash([leaf1, leaf2]);
    const hash34 = Poseidon.hash([leaf3, leaf4]);
    const expectedRoot = Poseidon.hash([hash12, hash34]);

    // Create tree with four elements
    const tree = new MerkleTree(elements);

    // Check height
    expect(tree.height).toBe(2);

    // Check if the root matches our expected calculation
    expect(tree.root.toString()).toBe(expectedRoot.toString());
  });

  test("should correctly handle tree with padding for non-power-of-2 elements (3 elements)", () => {
    // Create three elements (not a power of 2)
    const elements = [Field(10), Field(20), Field(30)];

    // Create the tree - it should pad to 4 elements internally
    const tree = new MerkleTree(elements);

    // Height should be based on padded size (4)
    expect(tree.height).toBe(2);

    // Manually calculate expected root with padding (Field(0))
    const h12 = Poseidon.hash([elements[0], elements[1]]);
    const h3_pad = Poseidon.hash([elements[2], Field(0)]); // Padded element
    const expectedRoot = Poseidon.hash([h12, h3_pad]);

    expect(tree.root.toString()).toBe(expectedRoot.toString());
  });

  test("should correctly handle larger trees (8 elements)", () => {
    const elements = Array(8)
      .fill(0)
      .map((_, i) => Field(i * 100 + 1));
    const tree = new MerkleTree(elements);

    expect(tree.height).toBe(3);

    // Manually calculate root (example for verification, can be tedious)
    const h01 = Poseidon.hash([elements[0], elements[1]]);
    const h23 = Poseidon.hash([elements[2], elements[3]]);
    const h45 = Poseidon.hash([elements[4], elements[5]]);
    const h67 = Poseidon.hash([elements[6], elements[7]]);
    const h0123 = Poseidon.hash([h01, h23]);
    const h4567 = Poseidon.hash([h45, h67]);
    const expectedRoot = Poseidon.hash([h0123, h4567]);

    expect(tree.root.toString()).toBe(expectedRoot.toString());
  });
});

describe("Merkle Tree Witness Verification", () => {
  test("should generate valid witness for element at index 0 (4 elements)", () => {
    const elements = [Field(111), Field(222), Field(333), Field(444)];
    const tree = new MerkleTree(elements);

    // Get witness path for the first element
    const path = tree.getWitnessAt(0);
    expect(path.length).toBe(tree.height); // Height is 2

    // Compute the root using the witness path
    const computedRoot = computeRootFromPath(elements[0], path);

    // Check that the computed root matches the actual root
    expect(computedRoot.toString()).toBe(tree.root.toString());
  });

  test("should generate valid witness for element at index 1 (4 elements)", () => {
    const elements = [Field(111), Field(222), Field(333), Field(444)];
    const tree = new MerkleTree(elements);

    // Get witness path for the second element
    const path = tree.getWitnessAt(1);
    expect(path.length).toBe(tree.height); // Height is 2

    // Compute the root using the witness path
    const computedRoot = computeRootFromPath(elements[1], path);

    // Check that the computed root matches the actual root
    expect(computedRoot.toString()).toBe(tree.root.toString());
  });

  test("should generate valid witness for element at index 2 (4 elements)", () => {
    const elements = [Field(111), Field(222), Field(333), Field(444)];
    const tree = new MerkleTree(elements);

    // Get witness path for the third element
    const path = tree.getWitnessAt(2);
    expect(path.length).toBe(tree.height); // Height is 2

    // Compute the root using the witness path
    const computedRoot = computeRootFromPath(elements[2], path);

    // Check that the computed root matches the actual root
    expect(computedRoot.toString()).toBe(tree.root.toString());
  });

  test("should throw error when requesting witness for out-of-bounds index", () => {
    const elements = [Field(111), Field(222)]; // 2 elements
    const tree = new MerkleTree(elements);

    // Check that getting witness for invalid index throws an error
    // Note: The check is against the *original* number of elements
    expect(() => tree.getWitnessAt(-1)).toThrow(
      `Index -1 out of bounds for 2 elements`,
    );
    expect(() => tree.getWitnessAt(2)).toThrow(
      `Index 2 out of bounds for 2 elements`, // Not 4 (padded size)
    );
    expect(() => tree.getWitnessAt(3)).toThrow(
      `Index 3 out of bounds for 2 elements`,
    );
  });

  test("should correctly generate witnesses for tree with padding (3 elements)", () => {
    // Create three elements (not a power of 2)
    const elements = [Field(10), Field(20), Field(30)];
    const tree = new MerkleTree(elements); // Pads to 4 internally

    // Get witnesses for all three original elements
    const path0 = tree.getWitnessAt(0);
    const path1 = tree.getWitnessAt(1);
    const path2 = tree.getWitnessAt(2);

    expect(path0.length).toBe(tree.height); // Height is 2
    expect(path1.length).toBe(tree.height);
    expect(path2.length).toBe(tree.height);

    // Verify all witnesses compute the correct root
    expect(computeRootFromPath(elements[0], path0).toString()).toBe(
      tree.root.toString(),
    );
    expect(computeRootFromPath(elements[1], path1).toString()).toBe(
      tree.root.toString(),
    );
    expect(computeRootFromPath(elements[2], path2).toString()).toBe(
      tree.root.toString(),
    );

    // Requesting witness for index 3 (padded element) should fail
    expect(() => tree.getWitnessAt(3)).toThrow(
      `Index 3 out of bounds for 3 elements`,
    );
  });

  test("should correctly generate witnesses for larger trees (8 elements)", () => {
    const elements = Array(8)
      .fill(0)
      .map((_, i) => Field(i * 50 + 5));
    const tree = new MerkleTree(elements);

    expect(tree.height).toBe(3);

    // Verify each leaf's witness
    for (let i = 0; i < elements.length; i++) {
      const path = tree.getWitnessAt(i);
      expect(path.length).toBe(tree.height);
      const computedRoot = computeRootFromPath(elements[i], path);
      expect(computedRoot.toString()).toBe(tree.root.toString());
    }
  });

  test("should maintain correct witness path structure (4 elements)", () => {
    const elements = [Field(1), Field(2), Field(3), Field(4)];
    const tree = new MerkleTree(elements);

    // Manually calculate intermediate hashes
    const h12 = Poseidon.hash([elements[0], elements[1]]);
    const h34 = Poseidon.hash([elements[2], elements[3]]);
    const root = Poseidon.hash([h12, h34]);
    expect(tree.root.toString()).toBe(root.toString());

    // Verify the witness for element at index 2 (value Field(3))
    const path2 = tree.getWitnessAt(2);

    // Path[0]: Neighbor is element at index 3 (Field(4)).
    //          Index 2 is left child, index 3 is right. Sibling is right.
    //          Hash is H(leaf, neighbor) => isNeighborLeft = false
    expect(path2[0].neighbor.toString()).toBe(elements[3].toString());
    expect(path2[0].isNeighborLeft.toBoolean()).toBe(false);

    // Path[1]: Neighbor is hash(el[0], el[1]) = h12.
    //          Node(2,3) is right child of root. Sibling is left child h12.
    //          Hash is H(neighbor, current_hash) => isNeighborLeft = true
    expect(path2[1].neighbor.toString()).toBe(h12.toString());
    expect(path2[1].isNeighborLeft.toBoolean()).toBe(true);
  });

  test("should create different witness paths for different elements", () => {
    const elements = [Field(5), Field(10), Field(15), Field(20)];
    const tree = new MerkleTree(elements);

    const path0 = tree.getWitnessAt(0);
    const path1 = tree.getWitnessAt(1);
    const path2 = tree.getWitnessAt(2);
    const path3 = tree.getWitnessAt(3);

    // Check neighbors at level 0 are different siblings
    expect(path0[0].neighbor.toString()).toBe(elements[1].toString()); // neighbor of 0 is 1
    expect(path1[0].neighbor.toString()).toBe(elements[0].toString()); // neighbor of 1 is 0
    expect(path2[0].neighbor.toString()).toBe(elements[3].toString()); // neighbor of 2 is 3
    expect(path3[0].neighbor.toString()).toBe(elements[2].toString()); // neighbor of 3 is 2

    expect(path0[0].neighbor.toString()).not.toBe(path1[0].neighbor.toString());
    expect(path2[0].neighbor.toString()).not.toBe(path3[0].neighbor.toString());

    // Check directionality flag is correct at level 0
    expect(path0[0].isNeighborLeft.toBoolean()).toBe(false); // Sibling 1 is right -> neighbor is right
    expect(path1[0].isNeighborLeft.toBoolean()).toBe(true); // Sibling 0 is left -> neighbor is left
    expect(path2[0].isNeighborLeft.toBoolean()).toBe(false); // Sibling 3 is right -> neighbor is right
    expect(path3[0].isNeighborLeft.toBoolean()).toBe(true); // Sibling 2 is left -> neighbor is left

    // Check neighbors at level 1
    const h01 = Poseidon.hash([elements[0], elements[1]]);
    const h23 = Poseidon.hash([elements[2], elements[3]]);
    expect(path0[1].neighbor.toString()).toBe(h23.toString()); // neighbor of node(0,1) is node(2,3)
    expect(path1[1].neighbor.toString()).toBe(h23.toString());
    expect(path2[1].neighbor.toString()).toBe(h01.toString()); // neighbor of node(2,3) is node(0,1)
    expect(path3[1].neighbor.toString()).toBe(h01.toString());

    // Check directionality at level 1
    expect(path0[1].isNeighborLeft.toBoolean()).toBe(false); // sibling node(2,3) is right
    expect(path1[1].isNeighborLeft.toBoolean()).toBe(false);
    expect(path2[1].isNeighborLeft.toBoolean()).toBe(true); // sibling node(0,1) is left
    expect(path3[1].isNeighborLeft.toBoolean()).toBe(true);
  });

  test("should have consistent behavior when recomputing the same tree", () => {
    const elements = [Field(42), Field(43), Field(44), Field(45)];

    // Create the same tree twice
    const tree1 = new MerkleTree(elements);
    const tree2 = new MerkleTree(elements);

    // Roots should match
    expect(tree1.root.toString()).toBe(tree2.root.toString());

    // Witnesses should produce identical paths
    for (let i = 0; i < elements.length; i++) {
      const path1 = tree1.getWitnessAt(i);
      const path2 = tree2.getWitnessAt(i);

      expect(path1.length).toBe(path2.length);
      for (let j = 0; j < path1.length; j++) {
        expect(path1[j].neighbor.toString()).toBe(path2[j].neighbor.toString());
        expect(path1[j].isNeighborLeft.toBoolean()).toBe(
          path2[j].isNeighborLeft.toBoolean(),
        );
      }
    }
  });

  test("should verify proof for modified elements fails", () => {
    const elements = [Field(1), Field(2), Field(3), Field(4)];
    const tree = new MerkleTree(elements);

    // Get witness path for element at index 1 (value Field(2))
    const path = tree.getWitnessAt(1);

    // Try to verify with the wrong element
    const modifiedElement = Field(99);
    const computedRoot = computeRootFromPath(modifiedElement, path);

    // This should not match the original root
    expect(computedRoot.toString()).not.toBe(tree.root.toString());
  });

  test("should get witness by value using getWitnessOf", () => {
    const elements = [Field(10), Field(20), Field(30), Field(40)];
    const tree = new MerkleTree(elements);
    const valueToFind = Field(30); // Element at index 2
    const index = 2;

    const pathByValue = tree.getWitnessOf(valueToFind);
    const pathByIndex = tree.getWitnessAt(index);

    // Check paths are identical
    expect(pathByValue.length).toBe(pathByIndex.length);
    for (let i = 0; i < pathByValue.length; i++) {
      expect(pathByValue[i].neighbor.toString()).toBe(
        pathByIndex[i].neighbor.toString(),
      );
      expect(pathByValue[i].isNeighborLeft.toBoolean()).toBe(
        pathByIndex[i].isNeighborLeft.toBoolean(),
      );
    }

    // Verify the computed root
    const computedRoot = computeRootFromPath(valueToFind, pathByValue);
    expect(computedRoot.toString()).toBe(tree.root.toString());
  });

  test("should throw error from getWitnessOf if value not found", () => {
    const elements = [Field(10), Field(20), Field(30), Field(40)];
    const tree = new MerkleTree(elements);
    const nonExistentValue = Field(99);

    expect(() => tree.getWitnessOf(nonExistentValue)).toThrow(
      `Value ${nonExistentValue.toString()} not found in the Merkle tree leaves.`,
    );
  });

  test("should handle duplicate elements correctly in getWitnessOf (finds first)", () => {
    const elements = [Field(10), Field(20), Field(10), Field(40)]; // Duplicate '10'
    const tree = new MerkleTree(elements);
    const valueToFind = Field(10);

    // Should find the first occurrence at index 0
    const path = tree.getWitnessOf(valueToFind);
    const pathForIndex0 = tree.getWitnessAt(0);

    // Check path matches the one for index 0
    expect(path.length).toBe(pathForIndex0.length);
    for (let i = 0; i < path.length; i++) {
      expect(path[i].neighbor.toString()).toBe(
        pathForIndex0[i].neighbor.toString(),
      );
      expect(path[i].isNeighborLeft.toBoolean()).toBe(
        pathForIndex0[i].isNeighborLeft.toBoolean(),
      );
    }

    // Verify computed root
    const computedRoot = computeRootFromPath(valueToFind, path);
    expect(computedRoot.toString()).toBe(tree.root.toString());
  });
});
