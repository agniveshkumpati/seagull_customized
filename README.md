# seagull_customized
This is customized version of Seagull tool built on top of 1.8.0 Official Developer Version to support MD5 Hash calculation for Diameter Protocol(Digest-HA1 AVP)

Official version of Seagull only support Radius, SIP protocols for Authentication. More details on http://gull.sourceforge.net/doc/core.html#Authentication
This repository has extended the authentication support for Diameter Protocol. 
For example, in MAA response, Digest-HA1 AVP(part of the grouped SIP-Digest-Authenticate AVP, which in turn is part of the SIP-Auth-Data-Item AVP) needs to be populated with MD5 Hash of username:realm:password.

A new function i.e. crypto_method_diameter() has been added which needs to be added in config file (/config/base_cx.xml).

<code>\<external-method\>
   \<defmethod name="authenticationDiameter"
              param="lib=lib_crypto.so;function=crypto_method_diameter"\>
   \</defmethod\>
\</external-method\></code>


Then in scenario file, AVP value can be set using set-value by passing username, realm and password

<code>\<set-value name="Digest-HA1" method="authenticationDiameter" format="username=$(username);realm=$(DestRealm);password=12345"\>\</set-value\></code>


E.g
<pre>
AVP: Digest-HA1(121) l=40 f=-M- val=0adbdd72b58264405ba95eca33cccaf6
    AVP Code: 121 Digest-HA1
    AVP Flags: 0x40, Mandatory: Set
    AVP Length: 40
    Digest-HA1: 0adbdd72b58264405ba95eca33cccaf6
    </pre>

<pre>
[agniveshkumpati]$ seagull
option -conf is mandatory
seagull
 Version tool   : 1.9.0
 This is customized version of Seagull tool to support MD5 Hash calculation for Diameter Protocol(Digest-HA1 AVP)
 Usage: param="lib=lib_crypto.so;function=crypto_method_diameter"
 Parameters: username, realm, password
 Author: Agnivesh Kumpati
</pre>
