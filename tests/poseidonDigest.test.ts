import { hashBytewisePoseidon } from "../unrolled_leaves/utils";
import { DynamicBytes } from "@egemengol/mina-credentials";
import { describe, expect, test } from "bun:test";
import { Bytes, Poseidon } from "o1js";

describe("test dynamic and static poseidon", () => {
  test("one", () => {
    class Dyn extends DynamicBytes({ maxLength: 7 }) {}
    const arr = Uint8Array.from([1, 2, 3]);
    const stat = Bytes.from(arr);
    const dyn = Dyn.fromBytes(arr);

    const staticDigest = Poseidon.hash(stat.bytes.map((b) => b.value));
    console.log(staticDigest.toBigInt());
    const dynDigest = hashBytewisePoseidon(dyn);
    console.log(dynDigest.toBigInt());
    expect(staticDigest.equals(dynDigest).toBoolean()).toBeTrue();
  });
});
