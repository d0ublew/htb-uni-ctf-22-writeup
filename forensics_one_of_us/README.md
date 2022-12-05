# One of Us (Forensics - Medium)

`.docm` file format denotes macro related challenge.

Use [ViperMonkey](https://github.com/decalage2/ViperMonkey/) to analyse and extract the macro source code.

Full output can be viewed on `vmonkey.log`

```sh
$ bash ViperMonkey/docker/dockermonkey.sh ./invisible_shields.docm
```

Analyzing the source code, we can see there is something about `Key` and `CreateEncryptor`. This is a hint to some kind of encryption method being used to encrypt the exfiltrated data. We can try to debug what is the key and what type of cipher is being used. To do that, we can use VB compiler in [replit.com](https://replit.com) and copy the `nkalPYSrDkoirG()` function and its dependencies.

We would need to tidy up the code as some of the syntax is deprecated and not supported by `replit` compiler, some of the `If-Else` statement is messed up, `Array()` could not be used as expression such that we need to implement our own function (`Arr()` and `ArrS()`), etc. Next, we also need to retrieve the value of this line of code, `PjJHmvDBocr = ovLKcDvvuvaxVc(ActiveDocument.Variables("gtrxGyKtbDzUEDng"))`, which can be found by unzipping the `.docm` file and grep for `gtrxGyK`. The result is on `word/settings.xml`

```xml
<w:docVars>
    <w:docVar
        w:name="gtrxGyKtbDzUEDng"
        w:val="eNS7GlezU9snp3ciGjUJ9HD0eo5arrhaNii/Jgh7Rq38gvvpitv8AHreIuCHDbXhLd1BlLceamykizs8G02DzoP5bZm0PWZkL80S8MfgzZKkTAWqU3oSdton381J023oFIgmK5mEI4c+F85DAOx+mOkrnEbqMaOzJ4EQ4lSM2LfCgqS7AXQDbwipi5KrDBRkfKO8Me3+6MQ5g/XK6b6e2W5HvaCGoWDe6P2crp90G3GTh0kAemmwX1OOhX1IaAeKe8GbBiyp++2WTalzSf1vCviI5a+jcyRw26L8DP6i4urW+YP902QZa43DZ6A+d8Zh438OogAeuuBaNXUgPEgPQpQaca+NDHco7sYPzmI4Fb1XJU9SS1xGw1gU06x8vZ2w6u8oqnQN/xxTvGjxXUV+X9fnxUGQsg64B85ekF+DPeJD/92LHqrK2wVSVYgHGqvwKY/Yshfu9t2fl74o7KDTFATUJa1AHmy9zsNuZPvvwbwG9iD1cHFJLnLemhWN+6vMoQiO/xUIYMWKGQk2D8+RiSvhlptUw2195E3e7K40WnXNLSyAMvW+ngfplr9T23xyapsNo8gz/MOdw0KWMB868kW9kAGQ5IXWPHGaE7H8hWB3t+1K5H861yr7u5BgZIUby3VU0gKV8EH2c0Gl7rCa6sFbiTtCXmV3r1A+Fm3vBMCG19X2YPN62VpHhRMobsfSEl5TezlLWYVA/HNP6G5VX8+sxdTdQOyk84SGtm8I5Ss6kL4bs/+zw/VdcaXr8IZSa5rsmSgRC4+mLHhPSBTZODowjHPJOZK++rnkqLWQTzIRiiRZZVXeSoVEIGSla44WBR7x2xJABJrRzCxKUg+ryslthKXjteBuF9JZZovMADo9uRVgtu7XYVahg9ujIR310KWMMKlr+rzsLAvvlMLPHGVrG8LDoHrbURxqjPlU3a5OppL//jZIRKGTHO353w8HNR/ly3P3Nw=="
    />
</w:docVars>
```

The tidied code can be found on `debug.vbs`.

After knowing that this is `RijndaelManaged` cryptography and the `Key` is `8xppg2oX68Bo6koL7hwSeC8bCEWvk540`, we try to get the other properties such as the `KeySize` which is `256`, `BlockSize` which is `256` too, and `Mode`, in this case it is `1` which means [`CBC` mode](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.ciphermode?view=net-7.0). As for the `IV` seems like it is derived from this line of code `BFSsfIzKNm = FVaFfsygaGuUBB(32)` and the output of `FVaFfsygaGuUBB()` function is random everytime.

Looking back at the content of `mail.txt` we can see that the body has 32 characters, a pipe symbol as separator `|`, and `base64` encoded string. These 32 characters might be the `IV` for the cipher as it matches the number in this function call, `FVaFfsygaGuUBB(32)`.

Next, we can write a simple `C#` program to decrypt it. This code can be found on `decrypt.cs`.

To compile `decrypt.cs` in Linux, we need to install the compiler from [https://www.mono-project.com/docs/about-mono/languages/csharp/](https://www.mono-project.com/docs/about-mono/languages/csharp/)

```sh
$ mcs ./decrypt.cs
$ mono ./decrypt.exe
Decrypted data:
Dear Austin,


I created an account for you in the forbidden spells server as you wished.

Your credentials are:

username: paustin
password: HTB{th3s3_sp3lls_4r3_t00_d4ng3r0us}

Sincerely,
P
```
