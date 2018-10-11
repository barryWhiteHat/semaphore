const TestableMiximus = artifacts.require("TestableMiximus");

const crypto = require('crypto');

const fs = require('fs');
const ffi = require('ffi');
const ref = require('ref');
const ArrayType = require('ref-array');
const BigNumber = require('bignumber.js');

var StringArray = ArrayType(ref.types.CString);

var libmiximus = ffi.Library('build/src/libmiximus', {
    // Retrieve depth of tree
    'miximus_tree_depth': [
        'size_t', []
    ],

    // Create a proof for the parameters
    'miximus_prove': [
        'string', [
            'string',       // pk_file
            'string',       // in_root
            'string',       // in_nullifier
            'string',       // in_exthash
            'string',       // in_spend_preimage
            'string',       // in_address
            StringArray,    // in_path
        ]
    ],

    // Verify a proof
    'miximus_verify': [
        'bool', [
            'string',   // vk_json
            'string',   // proof_json
        ]
    ]
});



contract("TestableMiximus", () => {
    describe("Deposit", () => {
        it("deposits then withdraws", async () => {
            let obj = await TestableMiximus.deployed();

            // Parameters for deposit
            let spend_preimage = new BigNumber(crypto.randomBytes(30).toString('hex'), 16);
            let nullifier = new BigNumber(crypto.randomBytes(30).toString('hex'), 16);
            let leaf_hash = await obj.MakeLeafHash.call(spend_preimage, nullifier);

            // Perform deposit
            let new_root_and_offset = await obj.Deposit.call(leaf_hash, {value: 1000000000000000000});
            await obj.Deposit.sendTransaction([leaf_hash], {value: 1000000000000000000});

            // Build parameters for proving
            let tmp = await obj.GetPath.call(new_root_and_offset[1]);
            let proof_address = tmp[1].map((_) => _ ? '1' : '0').join('');
            let proof_path = [];
            for( var i = 0; i < proof_address.length; i++ ) {
                proof_path.push( tmp[0][i].toString(10) );
            }
            let proof_root = await obj.GetRoot.call();
            proof_root = new_root_and_offset[0];

            let proof_exthash = await obj.GetExtHash.call();

            // Run prover
            let args = [
                "zksnark_element/miximus.pk.raw",
                proof_root.toString(10),
                nullifier.toString(10),
                proof_exthash.toString(10),
                spend_preimage.toString(10),
                proof_address,
                proof_path
            ];
            let proof_json = libmiximus.miximus_prove(...args);
            assert.notStrictEqual(proof_json, null);
            let proof = JSON.parse(proof_json);

            console.log(proof);

            // Verify whether or not our proof would be valid
            let proof_valid = obj.VerifyProof.call(
                proof_root.toString(10),
                nullifier.toString(10),
                proof_exthash.toString(10),
                proof.A,
                proof.B,
                proof.C);
            assert.strictEqual(proof_valid, true);
            
            // Then perform the withdraw
            console.log("Performing transaction!!");
            await obj.Withdraw(proof_root, nullifier, proof.A, proof.B, proof.C);
        });
    });
});
