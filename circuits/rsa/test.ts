import { Field } from "o1js";
import { Bigint4096, rsaDecrypt } from "./core";

import rsaParams from '../../files/rsa-test.json';

const params = {
  e: BigInt(rsaParams.e),
  n: BigInt(rsaParams.n),
};

const signatureRawData = rsaParams.s;

// reverse endianness of the signature.
const signatureRawDataAlt = (() => {
  const n = signatureRawData.length / 2;
  let r = '';
  for (let i = 0; i < n; i++) {
    r = `${signatureRawData.substr(2*i, 2)}${r}`
  }
  return r;
})();
// console.log('signature in reverse', signatureRawDataAlt);

const rsaSig = Bigint4096.from(BigInt(`0x${signatureRawData}`));
const modulus = Bigint4096.from(params.n);

const decoded = rsaDecrypt(rsaSig, modulus, Field.from(params.e));

const decodedBigInt = decoded.toBigint();

console.log('decoded hex: \n' + decodedBigInt.toString(16));
// see `decoded_hex_end0` and `decoded_hex_end1` (rsa-test.json)
console.log('decoded bin: \n' + decodedBigInt.toString(2));
// see `decoded_bin_end0` and `decoded_bin_end1` (rsa-test.json)

console.log('limbs : \n', decoded.fields.map(x => x.toString()));