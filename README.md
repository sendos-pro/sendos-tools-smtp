# sendos-tools-smtp

```
npm i sendos-tools-smtp
```

## Usage

``` js
const smtpCheck = require('sendos-tools-smtp');

smtpCheck
	.check('mx.yandex.ru')
	.then(function(result) {
		console.log(result);
	})
	.catch(function(err) {
		console.log(err);
	});
```