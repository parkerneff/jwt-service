package com.parkerneff.jwt;

import org.apache.commons.io.IOUtils;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;


@Configuration
public class JwtKeyConfiguration {
    @Value("${keystore.file}") String keystoreFile;
    @Value("${keystore.password}") String keystorePassword;

    @Bean
    public KeyInfo keyInfo() {
        KeyPairService keyPairService = new KeyPairService();
        keyPairService.setKeyStorePassword(keystorePassword);
        keyPairService.setKeyStoreFile(keystoreFile);
        return keyPairService.getKeyInfo();

    }


}




