[![Android Arsenal](https://img.shields.io/badge/Android%20Arsenal-Secured--Preference--Store-green.svg?style=true)](https://android-arsenal.com/details/1/4226)
 [![Download](https://api.bintray.com/packages/iammehedi/SecuredPreferenceStore/online.devliving%3Asecuredpreferencestore/images/download.svg) ](https://bintray.com/iammehedi/SecuredPreferenceStore/online.devliving%3Asecuredpreferencestore/_latestVersion)

# Secured-Preference-Store
A `SharedPreferences` wrapper for Android that encrypts the content with 256 bit AES encryption. The Encryption key is securely stored in device's KeyStore. You can also use the `EncryptionManager` class to encrypt & decrypt data out of the box. 

## Setup
### Maven
```
<dependency>
  <groupId>online.devliving</groupId>
  <artifactId>securedpreferencestore</artifactId>
  <version>latest_version</version>
  <type>pom</type>
</dependency>
````

### Gradle
```
compile 'online.devliving:securedpreferencestore:latest_version'
```

## Usage
Before using the store for the first time you must initialize it
```
//not mandatory, can be null too
String storeFileName = "securedStore";
//not mandatory, can be null too
String keyPrefix = "vss";
//it's better to provide one, and you need to provide the same key each time after the first time
byte[] seedKey = "SecuredSeedData".getBytes();
SecuredPreferenceStore.init(getApplicationContext(), storeFileName, keyPrefix, seedKey, new DefaultRecoveryHandler());
```
perhaps in `onCreate` of your `Application`  class or launcher `Activity`. 


You can use the secured preference store just like the way you use the default `SharedPreferences`
```java
SecuredPreferenceStore prefStore = SecuredPreferenceStore.getSharedInstance(getApplicationContext());

String textShort = prefStore.getString(TEXT_1, null);
String textLong = prefStore.getString(TEXT_2, null);
int numberInt = prefStore.getInt(NUMBER_1, 0);

prefStore.edit().putString(TEXT_1, text1.length() > 0 ? text1.getText().toString() : null).apply();
prefStore.edit().putString(TEXT_2, text2.length() > 0 ? text2.getText().toString() : null).apply();
prefStore.edit().putInt(NUMBER_1, number1.length() > 0 ? Integer.parseInt(number1.getText().toString().trim()) : 0).commit();
```
You can access the underlying encryption manager to encrypt/decrypt data:
```
EncryptionManager encryptionManager = SecuredPreferenceStore.getSharedInstance().getEncryptionManager();
```

You can also use a standalone `EncryptionManager` to encrypt/decrypt data on your own:
```java
SharedPreferences preferences = getSharedPreferences("backingStore", MODE_PRIVATE);
//not mandatory, can be null too
String keyAliasPrefix = "kp";
//not mandatory, can be null too
byte[] bitShiftKey = "bitShiftBits".getBytes();
EncryptionManager encryptionManager = new EncryptionManager(getApplicationContext(), preferences,
    keyAliasPrefix, bitShiftKey, new SecuredPreferenceStore.KeyStoreRecoveryNotifier() {
	@Override
	public boolean onRecoveryRequired(Exception e, KeyStore keyStore, List<String> keyAliases) {
	    return false;
	}
});
EncryptionManager.EncryptedData encryptedData = encryptionManager.encrypt(bytesToEncrypt);
byte[] decryptedData = encryptionManager.decrypt(encryptedData);
```
## Sample file content
A sample secured preference file will look like:

```xml
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

## NOTICE
The keys stored in the `KeyStore` aren't encrypted at rest to avoid [the issue](https://code.google.com/p/android/issues/detail?id=61989) where they get deleted when the device's lock screen protection changes. So if the device doesn't have a hardware backed key storage then the keys might be at a vulnerable state. You can read more about it [here](http://doridori.github.io/android-security-the-forgetful-keystore).

## Recovery
Keys get **deleted/locked in API levels lower than 21** and sometimes on later versions of the API on some devices when the user changes the device's security (screen lock protection). This phenomena is due to few issues in the `Keystore` implementation i.e [61989](https://code.google.com/p/android/issues/detail?id=61989), [177459](https://code.google.com/p/android/issues/detail?id=177459). Until those issues are fixed we need a way to recover from that scenario, otherwise the app itself might become unusable. To enable recovery you can add a `RecoveryHandler` to `SecuredPreferenceStore` before calling `getSharedInstance` for the first time. 

```java
SecuredPreferenceStore.setRecoveryHandler(new RecoveryHandler() {
            @Override
            protected void recover(Exception e, KeyStore keyStore, List<String> keyAliases, SharedPreferences preferences) {
                //Your recovery code goes here
            }
        });
```
A default recovery handler called `DefaultRecoveryHandler` is included in the library which deletes the keys and data, giving the library a chance to start over. 

## License

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	   http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.

	Copyright 2017 Mehedi Hasan Khan
