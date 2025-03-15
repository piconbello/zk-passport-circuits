import { Field, Provable, Struct, Bool, Poseidon } from "o1js";
import { StaticArray } from "@egemengol/mina-credentials";

function createMerkleWitnessClass(nofElements: number) {
  const N = Math.ceil(Math.log2(nofElements));

  return class MerkleWitness extends Struct({
    neighbors: StaticArray(Field, N),
    isNeigborLefts: StaticArray(Bool, N),
  }) {
    static height(): number {
      return N;
    }

    computeRoot(leaf: Field): Field {
      let cur = leaf;

      for (let i = Field(0); i < Field(N); i = i.add(1)) {
        const digest = Provable.if(
          this.isNeigborLefts.getOrUnconstrained(i),
          Poseidon.hash([this.neighbors.getOrUnconstrained(i), cur]),
          Poseidon.hash([cur, this.neighbors.getOrUnconstrained(i)]),
        );
        cur = digest;
      }

      return cur;
    }
  };
}

export function createMerkleTreeClass(nofElems: number) {
  const MerkleWitness = createMerkleWitnessClass(nofElems);
  const height = MerkleWitness.height();

  return class MerkleTree {
    private tree: Field[];

    constructor(private elements: Field[]) {
      const height = MerkleWitness.height();
      const leafCount = 2 ** height;
      const treeSize = 2 * leafCount - 1;

      this.tree = new Array(treeSize).fill(Field(0));

      const leafStartIndex = treeSize - leafCount;
      for (let i = 0; i < elements.length; i++) {
        this.tree[leafStartIndex + i] = elements[i];
      }

      for (let i = leafStartIndex - 1; i >= 0; i--) {
        const leftChildIndex = 2 * i + 1;
        const rightChildIndex = 2 * i + 2;
        this.tree[i] = Poseidon.hash([
          this.tree[leftChildIndex],
          this.tree[rightChildIndex],
        ]);
      }
    }

    get root(): Field {
      return this.tree[0];
    }

    getWitness(index: number): InstanceType<typeof MerkleWitness> {
      if (index < 0 || index >= this.elements.length) {
        throw new Error(
          `Index ${index} out of bounds for ${this.elements.length} elements`,
        );
      }

      const neighbors: Field[] = new Array(height);
      const isNeigborLefts: Bool[] = new Array(height);

      const leafCount = 2 ** height;
      const treeSize = 2 * leafCount - 1;
      const leafStartIndex = treeSize - leafCount;

      let currentIndex = leafStartIndex + index;

      for (let i = 0; i < height; i++) {
        const isRight = currentIndex % 2 === 0;
        const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;
        neighbors[i] = this.tree[siblingIndex];
        isNeigborLefts[i] = Bool(isRight);
        currentIndex = Math.floor((currentIndex - 1) / 2);
      }

      return new MerkleWitness({
        neighbors: new (StaticArray(Field, height))(neighbors),
        isNeigborLefts: new (StaticArray(Bool, height))(isNeigborLefts),
      });
    }

    static get Witness() {
      return MerkleWitness;
    }
  };
}
