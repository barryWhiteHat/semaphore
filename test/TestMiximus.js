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


let fq2_to_sol = (o) => {
    return [o[1], o[0]];
    //return [o[0], o[1]];
};


let g2_to_sol = (o) => {
    return [fq2_to_sol(o[0]), fq2_to_sol(o[1])];
};


let list_flatten = (l) => {
    return [].concat.apply([], l);
};


let vk_to_flat = (vk) => {
    return [
        list_flatten([
            vk.alpha[0], vk.alpha[0],
            list_flatten(g2_to_sol(vk.beta)),
            list_flatten(g2_to_sol(vk.gamma)),
            list_flatten(g2_to_sol(vk.delta)),
        ]),
        list_flatten(vk.gammaABC)
    ];
};


let proof_to_flat = (proof) => {
    return list_flatten([
        proof.A,
        list_flatten(g2_to_sol(proof.B)),
        proof.C
    ]);
};



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

            // Run prover to generate proof
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
            console.log("Proof:", proof);

            // Ensure proof inputs match ours
            assert.strictEqual('0x' + proof_root.toString(16), proof.input[0]);
            assert.strictEqual('0x' + nullifier.toString(16), proof.input[1]);
            assert.strictEqual('0x' + proof_exthash.toString(16), proof.input[2]);


            // Re-verify proof using native library
            let vk_json = fs.readFileSync('zksnark_element/miximus.vk.json');
            let proof_valid_native = libmiximus.miximus_verify(vk_json, proof_json);
            assert.strictEqual(proof_valid_native, true);
            let vk = JSON.parse(vk_json);

            // Verify VK and Proof together
            let [vk_flat, vk_flat_IC] = vk_to_flat(vk);
            let test_verify_args = [
                vk_flat,                // (alpha, beta, gamma, delta)
                vk_flat_IC,             // gammaABC[]
                proof_to_flat(proof),   // A B C
                [  
                    proof.input[0],
                    proof.input[1],
                    proof.input[2]
                ]
            ];
            console.log("Test args:", test_verify_args);
            let test_verify_result = await obj.TestVerify(...test_verify_args);
            console.log("Test Result: ", test_verify_result);

            // Verify whether or not our proof would be valid
            console.log("Checking if proof is valid")
            let proof_valid = obj.VerifyProof.call(
                proof.input[0],
                proof.input[1],
                proof.input[2],
                proof.A,
                proof.B,
                proof.C);
            assert.strictEqual(proof_valid, true);
            
            // Then perform the withdraw
            console.log("Performing transaction!!");
            await obj.Withdraw(
                proof_root.toString(10),
                nullifier.toString(10),
                proof.A,
                proof.B,
                proof.C);
        });
    });
});
