## Usage Patterns

The exposed usage patterns of our library

1. Generation of merkle trees of:
   - all possible pipeline vkDigests
   - masterlist pubkeys
2. Proof generation for a single passport
3. Validation of a single passport
4. ? Conversing with wallet and mobile app

Merkle tree generation can be done pre-publish and included in the library itself. It needs to be exposed though for verification purposes.

## May Benefit From

The library may benefit from having the following properties:

- Have proof caching, very useful for development. Can be filesystem (i.e. node) based.
- Should report which step it is currently in, for non-boring UI, since it will take around 10mins.
- Code generation of ZkPrograms. Hardcoding all variants is doable but labor-intensive and error-prone
- Cleanup the wasm state after generating leaves, since ZkProgram.compile() affects global state and uses huge amounts of memory.
- Salting the user data such that the proved data is not simply poseidon hash of DG1.
- Have the third merkle tree encompassing multiple pipeline and masterlist merkle roots.
- Make the masterlist stuff optional, for example TD1 DG1 documents like IDs dont have this. Or if you are working nationally already and dont care about ICAO masterlist and supply your own master pubkeys
- Rust emrtd-lib currently does:

  - Transform the document scan from mobile app to usable step-by-step data
  - Mock usable data
  - Parse masterlist

    Pure JS implementation may be useful for a tidy all-encompassing lib. Would require openssl I guess.  
    Or compile to rust to wasm, not sure about openssl though.

Would be too easy to implement these in horrible spagetti code. Lets brainstorm a bit

## Current Principle

The current underlying flow for a single pipeline variant is like the following:

Since we know the concrete variant, we pick the correct zkprograms.

Some steps are self-contained in a single leaf, some steps require multiple leaves.  
Multiple leaf steps all use the same verification key between them.

For any variant, we can and should fix the number of leaves each step, therefore the whole pipeline.  
Since it is static for that variant, the vkDigest for that pipeline can be calculated deterministically.

Leaves do not know each other in code level, they dont even verify any proofs or selfproofs.  
They just claim [left, right, vkDigest], where left and right are singular fields, vkDigest is irrelevant for leaves.

The logic is, when you see leaves A and B, if A.right == B.left,  
then you can merge them to have AB where A.left == AB.left and B.right == AB.right

Its the application's responsibility to ensure the pipeline's invariants to be upheld, by poseidon hashing all the intermediate state into these left and right fields.

We then run the Merger on this very structured simple proofs to reduce them to a single one. This proof has the singular vkDigest for this variant of documents, calculated by the Merger at each step deterministically.

Right now, we have a singular proof with [left, right, vkDigest]. Left is poseidon hash of DG1, right is merkle root of that masterlist version. vkDigest signifies the pipeline variant, like "sha2-256, sha2-512, secp256r1". This leaks information for that proof, like the issuer country.

Therefore, as the last step, in Merger, we obfuscate the vkDigest by turning it into a merkle tree contains proof. This merkle tree includes every pipeline vkDigest that we support, and therefore protects the concrete variant of the passport.

Now we have a single proof, from DG1 to a known masterlist version, not leaking any data apart from DG1 itself.
