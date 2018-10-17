const TestableMiximus = artifacts.require("TestableMiximus");

const crypto = require("crypto");

const fs = require("fs");
const ffi = require("ffi");
const ref = require("ref");
const ArrayType = require("ref-array");
const BigNumber = require("bignumber.js");

var StringArray = ArrayType(ref.types.CString);

var libmiximus = ffi.Library("build/src/libmiximus", {
    // Retrieve depth of tree
    "miximus_tree_depth": [
        "size_t", []
    ],

    // Create a proof for the parameters
    "miximus_prove": [
        "string", [
            "string",       // pk_file
            "string",       // in_root
            "string",       // in_nullifier
            "string",       // in_exthash
            "string",       // in_spend_preimage
            "string",       // in_address
            StringArray,    // in_path
        ]
    ],

    // Verify a proof
    "miximus_verify": [
        "bool", [
            "string",   // vk_json
            "string",   // proof_json
        ]
    ]
});



let list_flatten = (l) => {
    return [].concat.apply([], l);
};


let vk_to_flat = (vk) => {
    return [
        list_flatten([
            vk.alpha[0], vk.alpha[1],
            list_flatten(vk.beta),
            list_flatten(vk.gamma),
            list_flatten(vk.delta),
        ]),
        list_flatten(vk.gammaABC)
    ];
};


let proof_to_flat = (proof) => {
    return list_flatten([
        proof.A,
        list_flatten(proof.B),
        proof.C
    ]);
};


contract("TestableMiximus", () => {
    describe("Deposit", () => {
        it("deposits then withdraws", async () => {
            let obj = await TestableMiximus.deployed();

            // Parameters for deposit
            let spend_preimage = new BigNumber(crypto.randomBytes(30).toString("hex"), 16);
            let nullifier = new BigNumber(crypto.randomBytes(30).toString("hex"), 16);
            let leaf_hash = await obj.MakeLeafHash.call(spend_preimage, nullifier);


            // Perform deposit
            let new_root_and_offset = await obj.Deposit.call(leaf_hash, {value: 1000000000000000000});
            await obj.Deposit.sendTransaction([leaf_hash], {value: 1000000000000000000});


            // TODO: verify amount has been transferred


            // Build parameters for proving
            let tmp = await obj.GetPath.call(new_root_and_offset[1]);
            let proof_address = tmp[1].map((_) => _ ? "1" : "0").join("");
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


            // Ensure proof inputs match ours
            assert.strictEqual("0x" + proof_root.toString(16), proof.input[0]);
            assert.strictEqual("0x" + nullifier.toString(16), proof.input[1]);
            assert.strictEqual("0x" + proof_exthash.toString(16), proof.input[2]);


            // Re-verify proof using native library
            let vk_json = fs.readFileSync("zksnark_element/miximus.vk.json");
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
            let test_verify_result = await obj.TestVerify(...test_verify_args);
            assert.strictEqual(test_verify_result, true);


            // Verify whether or not our proof would be valid
            let proof_valid = await obj.VerifyProof.call(
                proof.input[0],
                proof.input[1],
                proof.input[2],
                proof_to_flat(proof));
            assert.strictEqual(proof_valid, true);


            // Verify nullifier doesn't exist
            let is_spent_b4_withdraw = await obj.IsSpent(nullifier.toString(10));
            assert.strictEqual(is_spent_b4_withdraw, false);


            // Then perform the withdraw
            await obj.Withdraw(
                proof_root.toString(10),
                nullifier.toString(10),
                proof_to_flat(proof));


            // Verify nullifier exists
            let is_spent = await obj.IsSpent(nullifier.toString(10));
            assert.strictEqual(is_spent, true);


            // TODO: verify balance has been increased
        });
    });
});
