const { execSync } = require("node:child_process");

const getYarnVersion = () => {
	try {
		const version = execSync("yarn --version").toString().trim();
		console.log(`Detected Yarn version: ${version}`);
		return version;
	} catch (error) {
		console.error(
			"Failed to detect Yarn version. Ensure Yarn is installed and in your PATH.",
		);
		process.exit(1);
	}
};

module.exports = {
	getYarnVersion,
};
