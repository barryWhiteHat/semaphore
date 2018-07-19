module.exports = {
	networks: {
		coverage: {
			host: "localhost",
			port: 8555,
			network_id: "*",
			gas: 0xFFFFFFFF,
			gasPrice: 0x1
		}
	},
	solc: {
		optimizer: {
			enabled: true,
			runs: 200
		}
	}
}