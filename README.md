# Semaphore
General Zero Knoledge Identity and Signaling, on and off chain.

[![Join the chat at https://gitter.im/barrywhitehat/Semaphore](https://gitter.im/barrywhitehat/Semaphore.svg)](https://gitter.im/barrywhitehat/miximus_eth?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

# Zero Knowledge Identity and Signaling

## Motiation
Having finished Miximus and deployed iit to the testnet I was planning to move onto my next zksnark project. However, given that I am able to make proofs about merkle trees I decided that it would be a good idea to hack together an anonymous Identity and signaling protocol using zkSNARKs because is seemed it would take quite a little amount of work after having figure out how to make Miximus. And it would be fun if a zero knoledge social network existed. This is a generatlization of Miximus.

## What is Miximus 
Miximus allows private transaction on Ethereum using zkSNARKs.

## What is a zkSNARK 

A zkSNARK is a way of proving that a computation was done correctly without reavealing what some or all of inputs to the computation are. Here we prove that a leaf is a member of a merkel tree without reavealing which leaf it is or the leaf pre-image.

## How miximus works

A user creates a transaction that sends 1 ETH to the contract which then adds a leaf to the on-chain merkle tree. The merkle tree is a list of permissions, each leaf is a "public key" and the person who has the "private key" (the leaf pre-image) is able to withdraw 1 ETH by providing a zkSNARK proof of a valid merkle tree path and a valid merkle root.

Each leaf can only be used once, the uniqueness tag prevents double-spends without revealing which of the leaves was spent - only that if a double spend occurs the uniqueness tag will be the same for both.


The leaf in defined as being the hash of two peices of information

1.  the nullfier (256 bits) which we will reveal later to prevent double spends
2.  The secret key (256 bits) which is a random number that we will never reveal. 

```
public(leaf) = HASH(private(nullifier) || shared(secret))
valid? = (public(root) == MERKLE-PROVE(public(leaf), private(path)))
```

A user creates a proof that they know the secret information of a leaf, and prove that that leaf is an element of the merkle tree defined by the merkel root in the smart contract. Remember because we us zksnarks:

1. There is no way to create this proof without knowing this private information.
2. No information is revealed. Except the information that we specifically decide the reveal.

They send the proof to the contract which verifies that:
1. The computation is correct 
2. That the merkle root that the zksnark produces is the same as the merkle root in the smart contract
3. That nullifier was not used before (to prevent double spends)

Then it sends the ether and saves to nullifier so it can't be used again.


## Using merkle tree for identity

All we need to do is replace step 1, and use a merkle tree that only includes leaves of people who have a reputation. Then a user can prove if they are a member of a group or not without revealing who they are. 

### Identitiy merkle root examples

Each leaf is 256 bits, which is the hash of another input nullifier = 256 bits, sk = 256 bits. The merkle tree depth is 29. 

The creation of these trees if trivial and I have a python script to do it (here)[]

The curation of these trees is outside the scope of this post tho I have some ideas of some ways to do it. 

1. Have a log in with github button and allow anyone who uses it to add a single leaf to a merkle tree. This is a basically proof of github identity but could be useful for testing.

3. Take a biometric of people and hash this at the second layer 28 with their public key. Then publish the hash of their biometric signed by their private key. This will produce a proof of individuality system. Please note that a persons membership in this merkle tree would be public to anyone who can get that biometric. I am unsure about the implications of this. At first thought it seems like acceptable. But need to consider more carefully. 

## Signalling

If we used the system of signing that miximus uses we would have two problems 

1. We could link a users signatures together because the same `nullifier` would be revealed twice.
2. We are not able to "sign" any data. We can only prove we are part of the merkel tree.

So to sign things we add the idea of a `signal` to be the sha256 hash of a json string (to be called the signal definition) which defines the rules of the Signal. This makes things super general so other people should be able to build their own signaling mechanimzims on top of this.

To prevent the linking of multiple identities each signature we define an `external_nullifier` which we use to prevent the linking of multiple commitments by having the same nullifier. This external nullifier should be set by the signal creator and changed refrenced in the `signal` definition.

The uniqueness tag is verified in the SNARK circuit by hashing the nullifier (the first half of your secret) with the uniqueness constraint `external_nullifier`. The uniqueness constraint should be unique to each `signal`, and possibly include values from the signal variables (e.g. `date` - to allow one signature per day).

The leaf preimage must never be revealed, this is the users "secret key", however the whole merkle tree and all leaves can be public knowledge without compromising either the users "secret key" or the anonymity that the SNARK merkle tree proof provides as proof of membership.

It is possible for a malicious actor to use the same nullifier in multiple signals, this could be used to reveal somebodys identity by providing them with a signal description that has the same `external_nullifier` as one you know they participated in - when they publish a SNARK proof the `unique_tag` will be the same - e.g. if you give signal to two people, one whom you know participated in vote A and one who didn't, if both publish their proofs the identity of the person you know who participated in vote A will be revealed - in addition to revealing which of the two signals that was published was theirs.

To avoid this a user could insist that all `external_nullifiers` that they sign include a timestamp and refuse to sign an `external_nullifier` that has a time stamp they had already signed. Or better still track the external\_nullifiers they signed and refuse to sign duplicates. 

Finally we add the idea of a `signal_variables` which is the sha256 of input variables so we can have to idea of a nonce or signal weight. The signal variables hash is included as an input to the SNARK circuit, if the signal variables are changed the circuit validation will fail.

### Signalling Generalization Details

The circuit supports a secret `internal_nullifier` and a public `external_nullifier` which prevents duplicate signatures. The `internal_nullifier` proves that the signer knows the leafs secret, and the `external_nullifier` binds that specific signature to an arbitrary condition such as signal ID and any uniqueness constraints.

With the generalized system, the following statements are true:

 * Identities can exist in multiple groups (merkle trees)
 * Identities can sign multiple signals
 * A signal requires membership of any one group
 * Each signal may be signed once, or multiple times if a 'uniqueness constraint' is included

The `external_nullifier` is constructed using a hash of the signal JSON description and any variables included in the unique constraint. e.g. for a one-signature-per-day rule the `external_nullifier` includes the signal GUID and the date (year-month-day).


## Examples 

### Voting

Simple voting where one user in a group gets a single say can already be done. We just need to ensure that all voters use the same external nullifiers. There for each element in the merkle tree can only vote once.

```json
{
    "group": "voting-group-a",
    "vars": {
        "weight": "int",
        "who": "str"
    },
    "cond": [
        ["weight", "between", [0, 10]],
        ["choice", "in", ["Godzilla", "Batman", "Superman"]]
    ]
}
```

This is implmented [here]()

### Anonymous social network

A more complicated example would be an anonamous social network. The simplist incarnation is that we set `external_nullifier` to be a time stamp that can only be updated once per day. This way each user can only make a single every day. And none of these posts can be linked together.

```json
{
    "group": "anon-social-network",
    "external_nullifier": ["date"],
    "vars": {
        "title": "str",
        "body": "str",
        "date": "date"
    }
}
```

The `date` external\_nullifier option adds the value of the `date` variable as an input to the uniqueness check so it will only allow one post per day per person registered within the `anon-blog-posters` group.

If the `date` field was changed to a `timestamp` value type, then any number of posts would be allowed per-day per-user.

## JSON specification

The signal is specified as a JSON document which describes its constraints and parameters in the simplest and most concise way.

 * `group` - Which named merkle tree does the signer prove they exist within
 * `vars` - Dictionary of `name => type` for any input
 * `external_nullifier` - List of variable names which constitute to the unique constraint of the signature
 * `cond` - List of conditions which the variables must satisfy, each condition is a list
   * `["name", "op", "rhs"]`
     * `name` - Variable name, from `vars`
     * `op` - Comparison operator, e.g. `in`, `between`, `<=`
     * `rhs` - Right hand side of comparison operator

## Future direction

I made a proof of concept for this [here]() which allows both on chain (ethereum) and offchain signalling. ** This code is a research-quality proof of concept, and has not yet undergone extensive review or testing. It is thus not suitable, as is, for use in critical or production systems. **

I am really excited to see what others build using this signalling system. I a particualy excited to see a zk social network and applications to blockchain governance. Unfortently I cannot take the lead on either of these projects. But I am more than happy to donate my time to anyone undertaking these noble endvours.

There are some limitation here
1. We only support binary reputation. As in all users have the same reputation in the merkle tree. We could hack together non binary reputation by adding a user multiple times into the Merkle tree. So user 1 would have reputation 1 and user 2 who has two entries in teh merkle tree has reputation 2. 
2. There is no way to burn reputation. 
3. There is no way to risk reputation.

## build instructions:

### build libsnark gadget and getting the proving key
get dependencies `git submodule update --init --recursive`
`mkdir build` 
`cd build`
`cmake .. && make`



### Running the tests
Start your prefered ethereum node, `cd tests` and run `python3 test.py` This will 
1. Generate verification keys, proving keys, This step takes a lot of ram and its likely your OS will kill it if you have a bunch of windows open.
2. Create a bunch of identies
3. Use thoes identiteis to create proofs
4. Verifity these proofs. 

## Examples
1. off\_chain\_signal.py is an example of how to create a merkle tree of identity's, create signals using these identity's, verify these proofs off chain. 
2. on\_chain\_verification.py creates a merkle tree of identity's makes proofs about these identity's and verifies them on chain. 

## References



