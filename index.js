var validate = require("./build/index.js");

exports.check = async (value) => {
	try {
		const smtp = new validate({value});
		const result = await smtp.check();
		return result;
	} catch (err) {
		console.log(err);
		throw new Error(err);
	}
};
