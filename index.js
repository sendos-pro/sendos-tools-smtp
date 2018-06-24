var validate = require("./build/index.js");

exports.check = async (domainOrEmail) => {
	try {
		const smtp = new validate({domainOrEmail});
		const result = await smtp.check();
		return result;
	} catch (err) {
		console.log(err);
		throw new Error(err);
	}
};
