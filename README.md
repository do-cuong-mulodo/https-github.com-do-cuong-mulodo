# Spring Boot Application Service Provider SAML 2.0 for Viewer

### Build SP-Docker

**Build Docker image**
- docker build -t saml2-springboot-app:0.0.1 .

**Start docker container**
- docker run -it --rm -p 8080:8080 -t saml2-springboot-app:0.0.1

### Build SP-Terminal
+ Install java, gradle; skip this step if you've aready done

- gradle build
- cd build/libs
- java -jar saml2-sp-springboot-viewer-0.0.1-SNAPSHOT.jar


### Step to test
1. access http://localhost:8080 -> Click login
2. checkin https://idp.ssocircle.com and SSO Login
3. browser will send redirect to /idp.ssocircle.com login page
4. login with username: do-cuong-mulodo password: docuongmulodo
5. From there checkin "I am not a robot" and click Continue SAML Single Sign on
6. browser will redirect to http://localhost:8080/dashboard and show authenticated information
7. You can enter the address bar URL http://localhost:8080/dashboard to reload page and see the dashboard page still there, don't need to login again
8. You can click logout from there and retest from step 1

### Note:
1. The certificate on https://idp.ssocircle.com/ seems to change on a fairly regular basis. This results in the following exception.
javax.net.ssl.SSLPeerUnverifiedException: SSL peer failed hostname validation for name: null. 
- To update the SSOCircle certificates within the keystore, just run:
cd src/main/resources/saml/ && sh ./update-certificate.sh

2. Change the port to be different from 8080 may lead to SSO error, idp.ssocircle.com does not redirect into your SP after logged in successfully. It may be a problem from idp.ssocircle.com, i am not sure why only localhost:8080 could work properly on my local machine

### References:
1. https://blog.imaginea.com/implementing-java-single-signon-with-saml
2. https://github.com/vdenotaris/spring-boot-security-saml-sample