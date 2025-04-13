import { Bytes } from "o1js";
import {
  createProvableBigint,
  EXP_BIT_COUNT,
} from "../../unrolled_meta/rsa/provableBigint";

export const ProvableBigint2048 = createProvableBigint(2048);
export type ProvableBigint2048 = typeof ProvableBigint2048;

export class RsaMessage2048 extends Bytes(256) {}
