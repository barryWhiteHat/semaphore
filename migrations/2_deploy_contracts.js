const Verifier = artifacts.require('Verifier.sol');
const TestableMiximus = artifacts.require('TestableMiximus.sol');


async function doDeploy( deployer, network )
{
	await deployer.deploy(Verifier);
	await deployer.link(Verifier, TestableMiximus);

    var vk = require('../zksnark_element/miximus.vk.json');
	await deployer.deploy(TestableMiximus,
		vk.alpha,
		vk.beta,
		vk.gamma,
		vk.delta,
		[].concat(...vk.gammaABC)
		);
}


module.exports = function (deployer, network) {
	deployer.then(async () => {
		await doDeploy(deployer, network);
	});
};
