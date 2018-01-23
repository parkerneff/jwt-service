keytool -genkey -keyalg RSA -alias k1 -keypass password  -keystore jwtkeys.jks -storepass password - validity 3650



keytool -export -keystore jwtkeys.jks -alias k1  -rfc  -file k1.cer