# sendos-tools-validate

```
npm i sendos-tools-validate
```

## Usage

``` js
var validate = require('sendos-tools-validate');

const check = async (emailAddress) => {
    try{
        const email = new validate({ emailAddress })
        const result = await email.check()
        return result
    }catch(err){
        throw new Error(err)
    }
}

check('testers72@gmail.com')
.then(function(result)
{
    console.log(result);
})
.catch(function(err)
{
    console.log(err);
})

```