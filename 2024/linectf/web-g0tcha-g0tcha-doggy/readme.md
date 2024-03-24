# Description

## Bug

Code Injection with some limitation (length, keyword, ...)

```java
            synchronized(this){
                rouletteB = thread(false) {
                    val dangerCommands = listOf("java", "eval", "util", "for", "while", "function", "const", "=>" )
                    val isDanger = dangerCommands.any { dateTime.contains(it) }
                    if (isDanger) {
                        throw CustomException("No Hack")
                    }

                    val script = Script.Builder()
                    .script("for(var tempvariable=0;tempvariable<5;tempvariable++){ bonus_number=Math.floor(secureRandom.nextDouble()*value)+1;java.lang.Thread.sleep(2);}")
                    .value(dateTime)
                    .tempVariable( variableBuiler() )
                    .dynamicVariable(StringBuilder().append(variableBuiler()).append(System.currentTimeMillis()).toString())
                    .build()
                    scriptEngineService.setSecureRandomSeed(userName)
                    scriptEngineService.runJS(script.script.toString())
                }

                rouletteA = thread(false) {
                    val value = dateTime.replace(Regex("^(\\d{1,3}).*"), "$1")
                    val script = Script.Builder()
                        .script("var end_no=variables.get('end_no');var start_no=variables.get('start_no');var tmp=[];for(var tempvariable=start_no;tempvariable<end_no;tempvariable++){tmp.push(Math.floor(secureRandom.nextDouble()*value)+1);Java.type('java.lang.Thread').sleep(50);}var agent_a_array=JSON.stringify(tmp);")
                        .value(value)
                        .tempVariable( variableBuiler() )
                        .dynamicVariable(StringBuilder().append(variableBuiler()).append(System.currentTimeMillis()).toString())
                        .build()
                        scriptEngineService.setSecureRandomSeed(userName)
                        scriptEngineService.runJS(script.script.toString())

                }
            }
```

And make a conditions to get the flag

```java
            if (userNumberExceptLast == result.gotchaNumbers && userBonus == result.bonusNumber)
            {
                val gotChaBaby : List<Long> = listOf(5,20)
                val gotChaHack : List<Long> = listOf(5,5,5)
                val gotChaPark : List<Long> = listOf(6,6,6)
                val gotChaKing : List<Long> = listOf(7,7,7)
                val gotChaTazza : List<Long> = listOf(8,8,8)
                val gotChaMaster : List<Long> = listOf(9,9,9)

                if( result.userNumbers == gotChaBaby){
                    resultMessage = "Gotcha baby!"
                    image = loadImage("flag.jpg")
                }else if( result.userNumbers == gotChaHack){
                    image = loadImage("flag.jpg")
                    resultMessage = "Gotcha hack"
                }else if( result.userNumbers == gotChaPark){
                    image = loadImage("flag.jpg")
                    resultMessage = "Gotcha Park!"
                }else if( result.userNumbers == gotChaKing){
                    image = loadImage("flag.jpg")
                    resultMessage = "Gotcha King"
                }else if( result.userNumbers == gotChaTazza){
                    image = loadImage("flag.jpg")
                    resultMessage = "Gotcha Tazza"
                }else if( result.userNumbers == gotChaMaster){
                    image = loadImage("flag.jpg")
                    resultMessage = "You are Master!!@#!@#!@#!@#!@#"
                }else {
                    resultMessage = "Luck is skill"
                }

            }
```

But we don't know how to solve it...

## (Unintended) Solution

`flag.jpg` has in web serving directory

Visit `http://35.243.76.165:11008/images/flag.jpg` and got flag

![flag.jpg](flag.jpg)

- **Flag: LINECTF{1c817e624ca6e4875e1a876aaf3466fc}**
