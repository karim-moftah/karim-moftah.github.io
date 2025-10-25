---
title: ClearRoute - 8kSec
date: 2025-9-3 00:00:00 +/-TTTT
categories: [8kSec]
tags: [8kSec, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase
---

<br />

**Description:**

**ClearRoute** is an iOS app designed to test your ability to intercept sensitive data without getting caught. The app attempts to send a POST request containing a hidden flag.

<br />

**Objective:**

Intercept the outgoing request to retrieve the flag. Modify, patch, or instrument the app to disable or evade any checks, allowing the request to go through. Intercept the POST data to extract the flag from the constructed key.

<br />

**Explore the application**

On launch, the app displays a **Send Secure Data** button.

![](/assets/img/8ksec/ClearRoute/3.jpg)

<br />

If you set the phone to route traffic through Burp, installed Burp’s certificate, and configured Burp’s proxy to listen on all interfaces, you’ll see the app show an error because a proxy is detected and no traffic will appear in Burp.

<br />





![](/assets/img/8ksec/ClearRoute/2.jpg)



<br />

**Reverse Engineering With Ghidra**

During static analysis, a function called **CheckForProxyAndSend()** was identified as responsible for handling the logic for sending or blocking requests.

![](/assets/img/8ksec/ClearRoute/3.png)

<br />

It invokes another function named **IsProxyEnabled()**, and based on the return value, either calls **SendSensitiveRequest()** to send the request or executes the *else* branch, which displays an error message when a proxy is detected.

![](/assets/img/8ksec/ClearRoute/4.png)



<br />

![](/assets/img/8ksec/ClearRoute/5.png)

<br />

**IsProxyEnabled()** is responsible for determining whether a proxy is configured. A return value of `1` indicates proxy usage, while `0` denotes that no proxy is active.

![](/assets/img/8ksec/ClearRoute/6.png)

<br />

**Method 1:**

The function `IsProxyEnabled()` is located at offset `0x6544` within `ClearRoute.debug.dylib` is hooked and forced to return `0` so the proxy check is bypassed, this Frida script performs the patch.

```javascript
var offset = ptr('0x6544'); // is proxy enabled
var t_module = 'ClearRoute.debug.dylib';

var base = Module.getBaseAddress(t_module);
if (base === null) {
    throw new Error('Module not found: ' + t_module);
}

var target = base.add(offset);

Interceptor.attach(target, {
    onEnter: function (args) {
    },
    onLeave: function(retval) {
    	retval.replace(0x0);
	}
});
```

<br />

Spawn the app with Frida and press **Send Secure Data**. it displays a success message despite the proxy being active.

![](/assets/img/8ksec/ClearRoute/1.jpg)

<br />

You should now see the HTTP request captured by Burp.

![](/assets/img/8ksec/ClearRoute/1.png)



**Flag:** CTF{no_proxies_allowed}



<br /><br />





**Method 2:**

`TBZ w0, #0, LAB_0000564c` is a conditional branch that tests bit 0 of `w0` and branches if it’s zero. Replacing it with `B LAB_0000564c` forces an unconditional jump to the same label, effectively forcing the branch to always be taken regardless of `w0`.

<br />

![](/assets/img/8ksec/ClearRoute/2.png)

<br />

```javascript
// Replace TBZ at module+0x5524 with an unconditional B to module+0x564c

const t_module = 'ClearRoute.debug.dylib';
const instr_offset = ptr('0x5524'); // location of TBZ to patch
const target_label_offset = ptr('0x564c'); // destination label LAB_0000564c

// Find module base
const base = Module.findBaseAddress(t_module);
if (base === null) {
    throw new Error('Module not found: ' + t_module);
}

const instr_addr = base.add(instr_offset);
const dest_addr = base.add(target_label_offset);

console.log('[*] module base:   ', base);
console.log('[*] instr address: ', instr_addr);
console.log('[*] dest address:  ', dest_addr);

// Save original bytes (4 bytes instruction)
const origBytes = Memory.readByteArray(instr_addr, 4);
console.log('[*] original bytes:', hexdump(origBytes, { offset: 0, length: 4 }));

// Compute branch immediate for B (imm26)
// ARM64 B encoding: opcode top 6 bits = 0b000101 (0x5), imm26 in lower 26 bits.
// imm26 = (dest - instr) / 4  (signed)
function computeBEncoding(fromPtr, toPtr) {
    // difference in bytes (signed)
    const diff = ptr(toPtr).sub(ptr(fromPtr)).toInt32(); // safe: branch range fits 28 bits
    // imm must be word-aligned and divided by 4
    if ((diff % 4) !== 0) {
        throw new Error('Branch target is not 4-byte aligned relative to instruction');
    }
    // imm26 signed value
    const imm = diff / 4;

    // check range: signed 26-bit -> -(1<<25) .. (1<<25)-1
    const min = -(1 << 25);
    const max =  (1 << 25) - 1;
    if (imm < min || imm > max) {
        throw new Error('Branch offset out of range for 26-bit immediate: ' + imm);
    }

    // mask into 26-bit two's complement representation
    const imm26 = imm & 0x03ffffff;

    // opcode for B = 0b000101 = 0x5 in top 6 bits
    const opcode = 0x5 << 26;

    // final 32-bit instruction word (little-endian write)
    const instrWord = (opcode | imm26) >>> 0; // unsigned 32-bit
    return instrWord;
}

try {
    const bInstr = computeBEncoding(instr_addr, dest_addr);
    console.log('[*] B instruction (word): 0x' + bInstr.toString(16));

    // Make memory writable/executable
    Memory.protect(instr_addr, 4, 'rwx');

    // Write the instruction (little-endian)
    instr_addr.writeU32(bInstr);

    // Optionally restore to rx (r-x) after patch
    Memory.protect(instr_addr, 4, 'r-x');

    console.log('[+] Patched TBZ -> B successfully at', instr_addr);
    console.log('[*] new bytes:', hexdump(instr_addr.readByteArray(4), { offset: 0, length: 4 }));

} catch (err) {
    console.error('[!] Patch failed:', err.message);
    // if we changed memory and want to restore, you could write origBytes back:
    try {
        Memory.protect(instr_addr, 4, 'rwx');
        Memory.writeByteArray(instr_addr, origBytes);
        Memory.protect(instr_addr, 4, 'r-x');
        console.log('[*] Original bytes restored.');
    } catch (restoreErr) {
        console.error('[!] Failed to restore original bytes:', restoreErr.message);
    }
}
```

output

```
[iOS Device::com.8ksec.ClearRoute.W46SY5ZJ6Z ]-> [*] module base:    0x1025e4000
[*] instr address:  0x1025e9520
[*] original bytes:            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  09 04 00 94                                      ....
[+] Patched BL -> MOVZ X0,#0 at 0x1025e9520
[*] new bytes:            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  00 00 80 d2                                      ....
[iOS Device::com.8ksec.ClearRoute.W46SY5ZJ6Z ]->

```

<br /><br />



**Method 3:**

By replacing the call to `IsProxyEnabled()` with `MOVZ X0, #0`, the `x0` register is set to 0. As a result, the following `tbz w0,#0x0,LAB_0000564c` instruction branches to `LAB_0000564c`, which executes the code that sends the request.

![](/assets/img/8ksec/ClearRoute/7.png)

<br />

```javascript
// Replace BL at module+0x5520 with MOVZ X0, #0 (zero X0)

const t_module = 'ClearRoute.debug.dylib';
const instr_offset = ptr('0x5520'); // location to patch (BL)
const instr_size = 4; // 4-byte ARM64 instruction

// find module base
const base = Module.findBaseAddress(t_module);
if (base === null) {
    throw new Error('Module not found: ' + t_module);
}

const instr_addr = base.add(instr_offset);
console.log('[*] module base:   ', base);
console.log('[*] instr address: ', instr_addr);

// Backup original bytes
const origBytes = Memory.readByteArray(instr_addr, instr_size);
console.log('[*] original bytes:', hexdump(origBytes, { offset: 0, length: instr_size }));

// Encoding for MOVZ X0, #0 (imm16 = 0, Rd = X0)
// MOVZ (imm16) opcode base: 0xD2800000 -> MOVZ X0, #0
const MOVZ_X0_0 = 0xD2800000;

try {
    // Make page writable/executable
    Memory.protect(instr_addr, instr_size, 'rwx');

    // Write the MOVZ instruction (little-endian)
    instr_addr.writeU32(MOVZ_X0_0 >>> 0);

    // Optionally restore to read+execute only
    Memory.protect(instr_addr, instr_size, 'r-x');

    console.log('[+] Patched BL -> MOVZ X0,#0 at', instr_addr);
    console.log('[*] new bytes:', hexdump(instr_addr.readByteArray(instr_size), { offset: 0, length: instr_size }));

} catch (err) {
    console.error('[!] Patch failed:', err.message);
    // Attempt to restore original bytes if something went wrong
    try {
        Memory.protect(instr_addr, instr_size, 'rwx');
        Memory.writeByteArray(instr_addr, origBytes);
        Memory.protect(instr_addr, instr_size, 'r-x');
        console.log('[*] Original bytes restored.');
    } catch (restoreErr) {
        console.error('[!] Failed to restore original bytes:', restoreErr.message);
    }
}

// Optional helper to restore original bytes later (call restoreOriginal() from console/RPC)
rpc.exports = {
    restoreoriginal: function () {
        try {
            Memory.protect(instr_addr, instr_size, 'rwx');
            Memory.writeByteArray(instr_addr, origBytes);
            Memory.protect(instr_addr, instr_size, 'r-x');
            return 'restored';
        } catch (e) {
            return 'restore failed: ' + e.message;
        }
    }
};
```

output

```
Spawning `com.8ksec.ClearRoute.W46SY5ZJ6Z`...                           
[*] module base:    0x1020cc000
[*] instr address:  0x1020d1520
[*] original bytes:            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  09 04 00 94                                      ....
[+] Patched BL -> MOVZ X0,#0 at 0x1020d1520
[*] new bytes:            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  00 00 80 d2                                      ....
Spawned `com.8ksec.ClearRoute.W46SY5ZJ6Z`. Resuming main thread!  
```



<br /><br />



**Method 4:**

By overwriting `b LAB_0000552c` with `b LAB_0000564c`, the program is redirected to `LAB_0000564c`, which executes the request-sending code.

<br />

![](/assets/img/8ksec/ClearRoute/8.png)

<br />

```javascript
// Replace instruction at module+0x5528 with B to module+0x564c

const t_module = 'ClearRoute.debug.dylib';
const instr_offset = ptr('0x5528'); // instruction to patch (currently B to 0x552c)
const dest_offset  = ptr('0x564c'); // new destination LAB_0000564c
const INSTR_SIZE = 4;

// find module base
const base = Module.findBaseAddress(t_module);
if (base === null) {
    throw new Error('Module not found: ' + t_module);
}

const instr_addr = base.add(instr_offset);
const dest_addr  = base.add(dest_offset);

console.log('[*] module base:   ', base);
console.log('[*] instr address: ', instr_addr);
console.log('[*] dest address:  ', dest_addr);

// backup original bytes
const origBytes = Memory.readByteArray(instr_addr, INSTR_SIZE);
console.log('[*] original bytes:', hexdump(origBytes, { offset: 0, length: INSTR_SIZE }));

// Compute ARM64 B encoding
// B has opcode top6 = 0b000101 (0x5), imm26 in low 26 bits.
// imm26 = (dest - from) / 4 (signed)
function computeBEncoding(fromPtr, toPtr) {
    // difference in bytes (signed 32-bit is OK for typical ranges; we'll check 26-bit range later)
    // Use toInt32 to get signed 32-bit diff (Frida NativePointer API).
    const diff = ptr(toPtr).sub(ptr(fromPtr)).toInt32();

    if ((diff % 4) !== 0) {
        throw new Error('Branch target is not 4-byte aligned relative to instruction: diff=' + diff);
    }

    const imm = diff / 4; // signed

    // signed 26-bit range: -(1<<25) .. (1<<25)-1
    const min = -(1 << 25);
    const max =  (1 << 25) - 1;
    if (imm < min || imm > max) {
        throw new Error('Branch offset out of range for 26-bit immediate: ' + imm);
    }

    // produce 26-bit two's complement representation
    const imm26 = imm & 0x03ffffff;

    // opcode for B in top 6 bits: 0b000101 => 0x5
    const opcode = 0x5 << 26;

    const instrWord = (opcode | imm26) >>> 0;
    return instrWord;
}

try {
    const bInstr = computeBEncoding(instr_addr, dest_addr);
    console.log('[*] computed B instruction word: 0x' + bInstr.toString(16));

    // make writable
    Memory.protect(instr_addr, INSTR_SIZE, 'rwx');

    // write instruction (little-endian)
    instr_addr.writeU32(bInstr);

    // restore protections to read+exec
    Memory.protect(instr_addr, INSTR_SIZE, 'r-x');

    console.log('[+] Patched instruction at', instr_addr, 'to B', dest_addr);
    console.log('[*] new bytes:', hexdump(instr_addr.readByteArray(INSTR_SIZE), { offset: 0, length: INSTR_SIZE }));

} catch (err) {
    console.error('[!] Patch failed:', err.message);

    // attempt restore if we changed memory
    try {
        Memory.protect(instr_addr, INSTR_SIZE, 'rwx');
        Memory.writeByteArray(instr_addr, origBytes);
        Memory.protect(instr_addr, INSTR_SIZE, 'r-x');
        console.log('[*] Original bytes restored.');
    } catch (restoreErr) {
        console.error('[!] Failed to restore original bytes:', restoreErr.message);
    }
}

// RPC to restore original bytes if needed
rpc.exports = {
    restoreoriginal: function () {
        try {
            Memory.protect(instr_addr, INSTR_SIZE, 'rwx');
            Memory.writeByteArray(instr_addr, origBytes);
            Memory.protect(instr_addr, INSTR_SIZE, 'r-x');
            return 'restored';
        } catch (e) {
            return 'restore failed: ' + e.message;
        }
    }
};
```

output

```
Spawning `com.8ksec.ClearRoute.W46SY5ZJ6Z`...                           
[*] module base:    0x104cd4000
[*] instr address:  0x104cd9528
[*] dest address:   0x104cd964c
[*] original bytes:            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  01 00 00 14                                      ....
[*] computed B instruction word: 0x14000049
[+] Patched instruction at 0x104cd9528 to B 0x104cd964c
[*] new bytes:            0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  49 00 00 14                                      I...
Spawned `com.8ksec.ClearRoute.W46SY5ZJ6Z`. Resuming main thread! 
```

