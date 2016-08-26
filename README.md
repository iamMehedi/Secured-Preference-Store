[ ![Download](https://api.bintray.com/packages/iammehedi/SecuredPreferenceStore/online.devliving%3Asecuredpreferencestore/images/download.svg) ](https://bintray.com/iammehedi/SecuredPreferenceStore/online.devliving%3Asecuredpreferencestore/_latestVersion)
# Secured-Preference-Store
A `SharedPreferences` wrapper for Android that encrypts the content with 256 bit AES encryption. The Encryption key is securely stored in device's KeyStore.

##Usage
###Maven
```
<dependency>
  <groupId>online.devliving</groupId>
  <artifactId>securedpreferencestore</artifactId>
  <version>0.1.1</version>
  <type>pom</type>
</dependency>
```

###Gradle
```
compile 'online.devliving:securedpreferencestore:0.1.1'
```

###Sample
A sample secured preference file will look like:

```
<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="11CD15241CB4D6F953FA27C76F72C10920C5FADF14FF2824104FA5D67D25B43C">ZMnr87IlDKg81hKw2SQ6Lw==]dhP/ymX7CMSaCkP6jQvNig==</string>
    <string name="C8D076EFD8542A5F02F86B176F667B42BFB9B1472E974E6AF31EB27CEA5689D4">JQ6Y4TQ/Y3iYw7KtatkqAg==]P+gpavV0MXiy1Qg0UHlBMg==</string>
    <string name="F2AA713F406544A3E9ABA20A32364FA29613F01C867B3D922A85DF4FA54FA13D">jMH1Wjnk0vehHOogT27HRA==]e8UHX1ihYjtP6Cv8dWdHLBptLwowt6IojKYa+1jkeH4=</string>
    <string name="C06C6027E72B7CE947885F6ADE3A73E338881197DBE02D8B7B7248F629BE26DA">EAGwO8u2ZPdxwdpAwPlu6A==]797VOGtpzDBO1ZU3m+Sb1A==</string>
    <string name="33188AFFEC74B412765C3C86859DE4620B5427C774D92F9026D95A7A8AAE1F96">s0b5h8XNnerci5AtallCQziSbqpm+ndjIsAQQadSxM+xzw7865sE3P+hbxGmMAQQj0kK35/C//eA
MXuQ0N/F+oapBiDIKdRt2GJB3wJ+eshuh6TcEv+J8NQhqn1eO2fdao353XthHpRomIeGEWLvB4Yd
7G5YYIajLWOGWzQVsMTg1eqdcJ7+BAMXdOdWhjTTo91NvhvykgLMC03FsePOZ/X8ej4vByH1i0en
hJCiChk90AQ9FhSkaF/Oum9KoWqg7NU0PGurK755VZflXfyn1vZ8hhTulW7BrA2o9HvT9tbju+bk
4yJ5lMxgS6o4b+0tqo+H4TPOUiZPgehTwsrzJg==
    </string>
    <string name="9DCB904DFDA83286B41A329A7D8648B0BFF73C63E844C88800B2AA5119204845">XPuUd1t97pnwsOzzHY3OCA==]xqXJrEfcgDhYo2K4TTAvY9IQwP/tGctd4Fa1JT/1sB8=</string>
</map>
``` 