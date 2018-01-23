package com.parkerneff.jwt;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;


import java.security.*;
import java.security.cert.Certificate;

import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

public class KeyPairService {
    @Getter
    @Setter
    private String keyStoreFile;
    @Getter
    @Setter
    private String keyStorePassword;

    private Log log = LogFactory.getLog(KeyPairService.class);

    public KeyInfo getKeyInfo() {
        Map<String, PrivateKey> privateKeyMap = new LinkedHashMap<>();
        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet();


        try {
            Resource resource = new ClassPathResource("jwtkeys.jks");
            KeyStore keyStore = KeyStore.getInstance("JKS");

            keyStore.load(resource.getInputStream(), "password".toCharArray());
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                log.info("key=" + alias);
                try {
                    Key key = keyStore.getKey(alias, "password".toCharArray());
                    if (key instanceof PrivateKey) {
                        Certificate cert = keyStore.getCertificate(alias);
                        PublicKey publicKey = cert.getPublicKey();
                        RsaJsonWebKey rsaJwk = (RsaJsonWebKey) PublicJsonWebKey.Factory.newPublicJwk(publicKey);
                        rsaJwk.setKeyId(alias);
                        jsonWebKeySet.addJsonWebKey(rsaJwk);
                        privateKeyMap.put(alias, (PrivateKey) key);

                    }


                } catch (UnrecoverableKeyException e) {
                    e.printStackTrace();
                }
            }
            return new KeyInfo(jsonWebKeySet, privateKeyMap);
        } catch (Exception e) {
            log.fatal(e.getMessage());

            return null;
        }

    }
}
