import { test, describe, expect } from "bun:test";

import { Hash256, Hash256Proof, hashProvable256 } from "../circuits/hash256";
import { Head256, Head256Input, Head256Proof } from "../circuits/head256";
import { parseBundle } from "../parseBundle";
import { DynamicBytes } from "@egemengol/mina-credentials";
import { Bytes } from "o1js";
// import { mapObject } from "./common";

describe("head 256", async () => {
  test("compiles hash", async () => {
    await Hash256.compile();
  });

  test("compiles head", async () => {
    await Head256.compile();
    // console.log(mapObject(await Head256.analyzeMethods(), (m) => m.summary()));
  });

  const bundleFrodo = parseBundle(
    await Bun.file("files/bundle.frodo.json").text(),
  );
  expect(bundleFrodo.digest_algo).toEqual("id-sha256");
  const ldsZk = DynamicBytes({ maxLength: 800 }).fromBytes(bundleFrodo.lds);

  let ldsHashProof: Hash256Proof;
  test("proves lds hash", async () => {
    ldsHashProof = await hashProvable256(ldsZk);
  });

  let headProof: Head256Proof;
  test("proves head", async () => {
    headProof = (
      await Head256.validateHead(
        new Head256Input({
          dg1: Bytes.from(bundleFrodo.dg1),
          signedAttrs: Bytes.from(bundleFrodo.signed_attrs),
        }),
        ldsZk,
        ldsHashProof,
      )
    ).proof;
  });

  test("validates head proof", async () => {
    expect(await Head256.verify(headProof)).toBeTrue();
  });
});
