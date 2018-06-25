# sendos-tools-smtp

```
npm i sendos-tools-smtp
```

## Usage

``` js
const smtpCheck = require('sendos-tools-smtp');

smtpCheck
	.check('testers72@gmail.com')
	.then(function(result) {
		console.log(result);
	})
	.catch(function(err) {
		console.log(err);
	});
```