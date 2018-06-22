var validate = require("./build/index.js");

exports.isValid = async (emailAddress) => {
	try {
		const email = new validate({ emailAddress });
		const result = await email.check();
		return result;
	} catch (err) {
		throw new Error(err);
	}
};