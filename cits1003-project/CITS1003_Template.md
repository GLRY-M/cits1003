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
A clear, and detailed description. 

### Step 2
### Step X

#### Flag Found
```bash
UWA{xxxxxxxxxx}
```

## EWT
### Step 1
A clear, and detailed description.  

### Step 2
### Step X

#### Flag Found
```bash
UWA{xxxxxxxxxx}
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
A clear, and detailed description.  

### Step 2
### Step X

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
