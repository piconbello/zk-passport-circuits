import { expect, test, describe } from "bun:test";
import {
  Rsa4096,
  verifyRsaProvable4096,
  generateRsaParams,
  rsaSign,
} from "../circuits/rsa";

describe("RSA 4096", async () => {
  test("compiles", async () => {
    await Rsa4096.compile();
  });

  // Generate test parameters
  const params = generateRsaParams(4096);
  const message = 123n;
  const signature = rsaSign(message, params.d, params.n);

  let rsaProof: Awaited<ReturnType<typeof verifyRsaProvable4096>>;

  test("proves and validates RSA signature", async () => {
    rsaProof = await verifyRsaProvable4096(
      params.n,
      params.e,
      signature,
      (status) => console.log(`Test status: ${status}`),
    );
    expect(await Rsa4096.verify(rsaProof)).toBeTrue();
  });

  test("validates correct signature in provable context", async () => {
    // The accumulator in the final state should equal the original message
    const finalState = rsaProof.publicOutput;
    expect(finalState.acc.toBigint()).toEqual(message);
  });

  test("rejects invalid signature", async () => {
    const invalidSignature = signature + 1n;
    const proof = await verifyRsaProvable4096(
      params.n,
      params.e,
      invalidSignature,
      (status) => console.log(`Test status: ${status}`),
    );
    expect(proof.publicOutput.acc.toBigint() !== message);
  });
});
