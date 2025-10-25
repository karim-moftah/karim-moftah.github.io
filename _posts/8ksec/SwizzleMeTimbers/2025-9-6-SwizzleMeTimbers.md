---
title: SwizzleMeTimbers - 8kSec
date: 2025-9-6 00:00:00 +/-TTTT
categories: [8kSec]
tags: [8kSec, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase
---

<br />

**Description:**

**SwizzleMeTimbers** is a pirate-themed iOS app with a secret buried deep inside its view controller. A simple button reads “**Unlock Treasure**”, but it’s protected by a method that always returns false, unless you’re crafty enough to change its behavior at runtime.

<br />

**Objective:**

Bypass the app’s logic using dynamic instrumentation tools (e.g., Frida or Objective-C runtime) to change the behavior of a function at runtime and trigger the correct flag path.

<br />

**Restrictions**:

You must perform runtime manipulation to change how the app behaves.

<br />



**Explore the application**

Launching the app displays the message “Avast, ye hacker” and an “Unlock Treasure” button.

![](/assets/img/8ksec/SwizzleMeTimbers/3.jpg)

<br />

Pressing the button triggers a UIAlert with the message “That ain’t the pirate’s path.”

![](/assets/img/8ksec/SwizzleMeTimbers/2.jpg)



<br />

Reverse-engineering `SwizzleMeTimbers.debug.dylib` reveals an `if` check that tests a variable. if true it shows “That ain’t the pirate’s path,” otherwise it follows the `else` branch and reveals the flag.

![](/assets/img/8ksec/SwizzleMeTimbers/1.png)



<br />

```assembly
tbz x0, #0, LAB_000065b8
b   LAB_0000655c
```

`tbz x0, #0, LAB_000065b8` tests bit 0 (LSB) of `x0`.

- If **LSB == 0** → branch to `LAB_000065b8`.
- If **LSB == 1** → fall through to the next instruction.

The next instruction is `b LAB_0000655c`, an **unconditional branch** that always jumps to `LAB_0000655c`.

So the control flow is:

- `x0 & 1 == 0` → go to `LAB_000065b8` (likely the `"That ain't the pirate's path"` branch).
- `x0 & 1 == 1` → fall through and then the `b` sends execution to `LAB_0000655c` (likely the flag branch).

To force the *else* path (the branch taken when LSB==1), set the LSB of `x0` to `1` before the `tbz` executes.

<br />

This Frida script hooks the instruction at offset `0x6554` inside `SwizzleMeTimbers.debug.dylib`. to patch `x0` register. if `x0 == 0x0`, change it to `0x1` to trigger the flag branch.

```javascript
var offset = ptr('0x6554');
var t_module = 'SwizzleMeTimbers.debug.dylib';

var base = Module.getBaseAddress(t_module);
if (base === null) {
    throw new Error('Module not found: ' + t_module);
}

var target = base.add(offset);

Interceptor.attach(target, {
    onEnter: function (args) {
        // Read current x0
        var before = this.context.x0;
        console.log('[onEnter] x0 before: ' + before);

        // Check if x0 == 0x0 and set to 0x1 if so
        if (before.equals(ptr(0))) {
            this.context.x0 = ptr(1);
            console.log('[onEnter] x0 was 0x0 — changed to: ' + this.context.x0);
        } else {
            console.log('[onEnter] x0 unchanged');
        }
    }
});
```

<br />

Spawn the app with frida

```
└─# frida -U -f com.8ksec.SwizzleMeTimbers.W46SY5ZJ6Z -l 8ksec.js
     ____
    / _  |   Frida 16.1.4 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to iOS Device (id=4a6e3de083155aae4c1a3473ff2d8c76b254887b)
Spawning `com.8ksec.SwizzleMeTimbers.W46SY5ZJ6Z`...                     
Error hooking UIAlertController: TypeError: cannot read property 'returnType' of undefined
Spawned `com.8ksec.SwizzleMeTimbers.W46SY5ZJ6Z`. Resuming main thread!  
[iOS Device::com.8ksec.SwizzleMeTimbers.W46SY5ZJ6Z ]-> [onEnter] x0 before: 0x0
[onEnter] x0 was 0x0 — changed to: 0x1
```

<br />

![](/assets/img/8ksec/SwizzleMeTimbers/1.jpg)

<br />

**Flag:** `CTF{{Swizzle_mbers}}`
