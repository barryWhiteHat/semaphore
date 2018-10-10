const TestableMiximus = artifacts.require("TestableMiximus");

const crypto = require('crypto');

contract("TestableMiximus", () => {
	describe("Deposit", () => {
		it("deposits", async () => {
			let obj = await TestableMiximus.deployed();
			let preimage = crypto.randomBytes(30).toString('hex');
			let leaf = parseInt(preimage, 16);
			let deposit_result = await obj.Deposit.call(leaf, {value: 1000000000000000000});
		});
	});
});
