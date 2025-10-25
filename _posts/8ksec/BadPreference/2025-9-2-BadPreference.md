---
title: BadPreference - 8kSec
date: 2025-9-2 00:00:00 +/-TTTT
categories: [8kSec]
tags: [8kSec, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase
---

<br />

**Description:**

**BadPreference** looks like a clean, production-ready app until you flip the right switch. Somewhere in the app’s internal preferences lies a hidden mode that unlocks a secret flag, but it won’t reveal itself through the UI or static strings alone.

<br />

**Objective:**

- Discover and activate the app’s hidden debug mode to extract the flag.
- Manipulate the app’s internal settings or runtime behavior to enable a hidden debug state and uncover the embedded flag.

<br />

**Restrictions:**

- The flag only appears when the app believes it’s running in debug mode.
- Static reverse engineering alone won’t trigger it, you need to modify app state or interact with runtime data.
- No direct UI controls reveal or toggle the hidden mode.

<br />

**Explore the application**

When you launch the app, it displays a screen with a title indicating that it’s running in production mode, and no other buttons are shown.

<br />

![](/assets/img/8ksec/BadPreference/1.jpg)

<br />

<br />

**Reverse Engineering With Ghidra**

Through static analysis, the function located at offset **0x5668** in **BadPreference.debug.dylib** appears to implement the logic that determines whether to display the **production mode** or the **debug mode** screen.

![](/assets/img/8ksec/BadPreference/1.png)

<br />

**Instruction at `0x5864`:**

```assembly
e8 01 00 36     tbz w8, #0x0, LAB_000058a0
```

<br />

`TBZ` = *Test Bit and Branch if Zero*

This instruction checks **bit #0** of register **w8**.
 If that bit is **0**, the code **branches** to the label `LAB_000058a0`.
 If the bit is **1**, execution continues with the next instruction (at `0x5868`).

<br />

**Instruction at `0x5868`:**

```assembly
01 00 00 14     b LAB_0000586c
```

`B` = *Unconditional Branch*

This means: “Always jump to 0x586C.”

<br />

These two instructions test **bit #0** of register **w8**. If the bit is **0**, execution branches to the **production mode** path, otherwise, it proceeds to the **debug mode** path.

<br />

![](/assets/img/8ksec/BadPreference/2.png)

<br />

At offset **0x5864**, the `if` condition checks bit **#0** of register **w8**.
 If that bit is **0**, execution branches to **LAB_000058a0**; if it’s **1**, execution proceeds to the next instruction at **0x5868**.

We’ll hook this address to log the value of the **x8** register at runtime.

```javascript
var offset = ptr('0x5864'); 
var t_module = 'BadPreference.debug.dylib';

var base = Module.getBaseAddress(t_module);
if (base === null) {
    throw new Error('Module not found: ' + t_module);
}

var target = base.add(offset);

Interceptor.attach(target, {
    onEnter: function (args) {
          console.log("param x8: ", this.context.x8);
    }
});
```

The value of **x8** was observed to be **0**. we need to modify it to **1** in order to trigger the **debug mode** branch.

```
[iOS Device::com.8ksec.BadPreference.W46SY5ZJ6Z ]-> param x8:  0x0
```

<br />

Frida script that hooks offset `0x5864` and sets register `x8` to `1`, forcing the bit-test to take the debug-mode branch.

```javascript
var offset = ptr('0x5864'); 
var t_module = 'BadPreference.debug.dylib';

var base = Module.getBaseAddress(t_module);
if (base === null) {
    throw new Error('Module not found: ' + t_module);
}

var target = base.add(offset);

Interceptor.attach(target, {
    onEnter: function (args) {
          this.context.x8 = ptr(0x1);
          console.log("param x8: ", this.context.x8);
    }
});
```

<br />

![](/assets/img/8ksec/BadPreference/2.jpg)

<br />

These two instructions test bit **#0** of register **w8** and pick one of two code paths. `tbz w8,#0x0, LAB_0000613c` checks the least-significant bit of `w8`. if that bit is **0**, execution jumps to `LAB_0000613c` (which is the path that loads the preferences text **"Welcome to preferences Manager"**). If the bit is **1**, the `tbz` falls through to the next instruction, which is an unconditional branch `b LAB_00005b74`, so execution goes to the **flag branch** at `LAB_00005b74`.

<br />

![](/assets/img/8ksec/BadPreference/3.png)

<br />

We need to set register **x8** to `1` at offset **0x5b6c** so execution is forced to take the **flag** branch.

![](/assets/img/8ksec/BadPreference/4.png)

<br />

```javascript
var offset = ptr('0x5864'); 
var t_module = 'BadPreference.debug.dylib';

var base = Module.getBaseAddress(t_module);
if (base === null) {
    throw new Error('Module not found: ' + t_module);
}

var target = base.add(offset);

Interceptor.attach(target, {
    onEnter: function (args) {
          this.context.x8 = ptr(0x1);
    }
});


offset = ptr('0x5b6c'); 
target = base.add(offset);

Interceptor.attach(target, {
    onEnter: function (args) {
          this.context.x8 = ptr(0x1);
    }
});
```

<br />

![](/assets/img/8ksec/BadPreference/3.jpg)



<br />

**Flag:** CTF{the_prefs_are_bad}                                                                                                                                                                                                                  
