---
title: JWT attacks - PortSwigger
date: 2023-7-15 00:00:00 +/-TTTT
categories: [PortSwigger]
tags: [PortSwigger, writeup, penetration testing, JWT attacks]
---



<br />

### Table of Contents

- [JWT authentication bypass via unverified signature](#jwt-authentication-bypass-via-unverified-signature)
- [JWT authentication bypass via flawed signature verification](#jwt-authentication-bypass-via-flawed-signature-verification)
- [JWT authentication bypass via weak signing key](#jwt-authentication-bypass-via-weak-signing-key)
- [JWT authentication bypass via jwk header injection](#jwt-authentication-bypass-via-jwk-header-injection)
- [JWT authentication bypass via jku header injection](#jwt-authentication-bypass-via-jku-header-injection)



<br />

---



### [JWT authentication bypass via unverified signature](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-unverified-signature)

Goal : modify your session token to gain access to the admin panel at `/admin`, then delete the user `carlos`.

- login with your credentials `wiener : peter` 
- notice that the cookies contain field called session and contain JWT token
- if you decoded it , you would see that the token identifies you from your name
- <img src="/assets/img/portswigger/jwt/1_1.png" alt="jwt" style="zoom:80%;" />

<br />

- also you know that the token has 3 parts header , payload and signature . now we are interested in the payload part , you also need to know that it's just encoding in base64

<img src="/assets/img/portswigger/jwt/1_2.png" alt="jwt" style="zoom:80%;" />

<br />

- change the username from wiener to admin and encode it with base64 , you will get this 
  ```js
  eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluIiwiZXhwIjoxNjYwNzYwNTIzfQ
  ```

<img src="/assets/img/portswigger/jwt/1_3.png" alt="jwt" style="zoom:80%;" />

<br />

- change the token in session field in cookies to the new token and refresh the page

<img src="/assets/img/portswigger/jwt/1_4.png" alt="jwt" style="zoom:80%;" />

<br />

- you will notice that your username will be admin but the if you go to `/admin` , you still don't have permissions , also notice that the message tells you should login as `administrator` 
- so repeat the last step to generate new token with username `administrator` instead of `admin`

<img src="/assets/img/portswigger/jwt/1_5.png" alt="jwt" style="zoom:80%;" />

<br />

- set the session value to the new token ,refresh the page and now you can delete `carlos`'s account

  <img src="/assets/img/portswigger/jwt/1_6.png" alt="jwt" style="zoom:80%;" />



<br /><br />



------





### [JWT authentication bypass via flawed signature verification](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-flawed-signature-verification)

Goal : modify your session token to gain access to the admin panel at `/admin`, then delete the user `carlos`.



- we know from the description of the lab that the server is insecurely configured to accept unsigned JWTs , which means that we can ignore sending the signature part of the token and still accepts it 
- make `alg` to `none` ( because in this lab we don't need to verify the signature ) and `sub` to `administartor`
- you can modify the token directly from `json Web token` extension in Burpsuite

<img src="/assets/img/portswigger/jwt/2_1.png" alt="jwt" style="zoom:80%;" />

<br />

- get the header and payload parts of the token and make sure to keep the two dots to make the token valid 
  ```
  eyJraWQiOiJlMDkwMTAxNy03YWFkLTQ2NTUtODIxMi1mYThkYTA4MTVkMzIiLCJhbGciOiJub25lIn0.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6ImFkbWluaXN0cmF0b3IiLCJleHAiOjE2NjA3NzA3NDZ9.  
  ```

  <br />

- change the token in session field in cookies to the new token and refresh the page , you will have access to the admin panel and you can delete `carlos`'s account.



<br /><br />

---





### [JWT authentication bypass via weak signing key](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-weak-signing-key)

Goal : brute-force the website's secret key. Once you've obtained this, use it to sign a modified session token that gives you access to the admin panel at `/admin`, then delete the user `carlos`.

<br />

- login with your credentials `wiener : peter` 
- we know from the description of the lab that the secret key is very weak and we can crack it easily using this [wordlist](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list)
- use hashcat to crack the JWT token with this command

```bash
hashcat -a 0 -m 16500 <JWT token> <JWT wordlist>
```

<br />

```bash
hashcat -a 0 -m 16500 eyJraWQiOiJhYmQ2N2FmZC1iODA3LTQ3YjQtODNjNi0xMGUzYTY5NDAyMGEiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsInN1YiI6IndpZW5lciIsImV4cCI6MTY2MDgyNzA5NX0.MLBUFpTVqW9-8Zp9T1c0LhR_vioClp1L9IAYSd8tafE jwt.secrets.txt

```

<br />

- the secret key is `secret1`

<img src="/assets/img/portswigger/jwt/3_1.png" alt="jwt" style="zoom:80%;" />

<br />

- modify  the `sub` to `administartor` and write your secret key in the signature part

<img src="/assets/img/portswigger/jwt/3_2.png" alt="jwt" style="zoom:80%;" />



<br />

- now you have a valid JWT token 
- change the token in session field in cookies to the new token and refresh the page , you will have access to the admin panel and you can delete `carlos`'s account.

<br /><br />

------





### [JWT authentication bypass via jwk header injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jwk-header-injection)

Goal :  modify and sign a JWT that gives you access to the admin panel at `/admin`, then delete the user `carlos`.

- login with your credentials `wiener : peter` 
- we know from the description of the lab that the server supports the `jwk` parameter in the JWT header 
- servers  use `jwk` header parameter to embed their public key directly within the token itself in JWK format , misconfigured servers sometimes use any key that's embedded in the `jwk` parameter.
- go to the **JWT Editor Keys** tab in burpsuite
- [Generate a new RSA key.](https://portswigger.net/web-security/jwt/working-with-jwts-in-burp-suite#adding-new-signing-keys)
- Send a request containing a JWT to Burp Repeater.
- modify the token's payload `sub` from `wiener`  to  `administrator`
- Click **Attack**, then select **Embedded JWK**. When prompted, select your newly generated RSA key.
- by doing this we tell the misconfigured server to verify the token with the private key that we generated

<br />

<img src="/assets/img/portswigger/jwt/4_1.png" alt="jwt" style="zoom:80%;" />



<br />

- change the token in session field in cookies to the new token and refresh the page , you will have access to the admin panel and you can delete `carlos`'s account.
- this is the generated token with `jwk` parameter

<img src="/assets/img/portswigger/jwt/4_2.png" alt="jwt" style="zoom:80%;" />



<br /><br />





------



###  [JWT authentication bypass via jku header injection](https://portswigger.net/web-security/jwt/lab-jwt-authentication-bypass-via-jku-header-injection)

Goal : forge a JWT that gives you access to the admin panel at `/admin`, then delete the user `carlos`.

<br />

- login with your credentials `wiener : peter` 
- we know from the description of the lab that the server supports the `jku ` parameter in the JWT header 

> ```
>  The "jku" (JWK Set URL) Header Parameter is a URI [RFC3986] that
>    refers to a resource for a set of JSON-encoded public keys, one of
>    which corresponds to the key used to digitally sign the JWS.
> ```

<br />

- go to the **JWT Editor Keys** tab in burpsuite
- [Generate a new RSA key.](https://portswigger.net/web-security/jwt/working-with-jwts-in-burp-suite#adding-new-signing-keys)  ,right-click on the entry for the key that you just generated, then select **Copy Public Key as JWK**.
- go to your exploit server , modify File from `/exploit` to `/.well-known/jwks.json` and paste your public key in the body

<br />

<img src="/assets/img/portswigger/jwt/5_1.png" alt="jwt" style="zoom:80%;" />

- Send a request containing a JWT to Burp Repeater.
- modify the token's payload `sub` from `wiener`  to  `administrator`
- modify `kid` with the new one 
- add `jku` in the header with your exploit server link 

<br />

<img src="/assets/img/portswigger/jwt/5_2.png" alt="jwt" style="zoom:80%;" />

<br />

-  click **Sign**, then select the RSA key that you generated in the previous section.
- Make sure that the **Don't modify header** option is selected, then click **OK**. The modified token is now signed with the correct signature.
- change the token in session field in cookies to the new token and refresh the page , you will have access to the admin panel and you can delete `carlos`'s account.
- this is the generated token with `jku` parameter

<br />

<img src="/assets/img/portswigger/jwt/5_3.png" alt="jwt" style="zoom:80%;" />







