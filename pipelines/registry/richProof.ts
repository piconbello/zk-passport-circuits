import { Field, VerificationKey } from "o1js";
import { MergerProof } from "../../unrolled_meta/merger";

export type RichProof = {
  proof: MergerProof;
  vk: VerificationKey;
};

export function serializeRichProof(rp: RichProof): string {
  return JSON.stringify({
    proof: rp.proof.toJSON(),
    vk: {
      data: rp.vk.data,
      hash: rp.vk.hash.toString(),
    },
  });
}

export async function deserializeRichProof(j: string): Promise<RichProof> {
  const parsed = JSON.parse(j);
  return {
    proof: await MergerProof.fromJSON(parsed.proof),
    vk: {
      data: parsed.vk.data,
      hash: Field.from(parsed.vk.hash),
    },
  };
}
