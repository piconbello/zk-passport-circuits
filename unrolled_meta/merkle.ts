import { Field, Provable, Struct, Bool, Poseidon } from "o1js";

export function calcMerkleHeightFor(nofElements: number) {
  return Math.ceil(Math.log2(nofElements));
}

export interface Step {
  neighbor: Field;
  isNeighborLeft: Bool;
}

export class MerkleWitnessStep extends Struct({
  neighbor: Field,
  isNeighborLeft: Bool,
}) {
  calculateParentFor(val: Field): Field {
    return Provable.if(
      this.isNeighborLeft,
      Poseidon.hash([this.neighbor, val]),
      Poseidon.hash([val, this.neighbor]),
    );
  }
  static fromStep(step: Step) {
    return new MerkleWitnessStep({
      neighbor: step.neighbor,
      isNeighborLeft: step.isNeighborLeft,
    });
  }
}

export class MerkleTree {
  private tree: Field[];
  public readonly height: number;

  constructor(private elements: Field[]) {
    elements.forEach((element, index) => {
      if (
        element === null ||
        element === undefined ||
        !(element instanceof Field)
      ) {
        throw new Error(
          `Invalid element at index ${index}: must be a valid Field, got ${element}`,
        );
      }
    });
    this.height = calcMerkleHeightFor(elements.length);
    const leafCount = 2 ** this.height;
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

  getWitness(index: number) {
    if (index < 0 || index >= this.elements.length) {
      throw new Error(
        `Index ${index} out of bounds for ${this.elements.length} elements`,
      );
    }

    const path: Step[] = new Array(this.height);

    const leafCount = 2 ** this.height;
    const treeSize = 2 * leafCount - 1;
    const leafStartIndex = treeSize - leafCount;

    let currentIndex = leafStartIndex + index;

    for (let i = 0; i < this.height; i++) {
      const isRight = currentIndex % 2 === 0;
      const siblingIndex = isRight ? currentIndex - 1 : currentIndex + 1;
      path[i] = {
        neighbor: this.tree[siblingIndex],
        isNeighborLeft: Bool(isRight),
      };
      currentIndex = Math.floor((currentIndex - 1) / 2);
    }

    return path;
  }
}
