package com.parkerneff.jwt;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;


import java.security.*;
import java.security.cert.Certificate;

import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

public class KeyPairService {
    @Getter @Setter private String keyStoreFile;
    @Getter @Setter private String keyStorePassword;

    private Log log = LogFactory.getLog(KeyPairService.class);

    public Map<String, KeyPair> getKeyPairs() {
            Map<String, KeyPair> keyMap = new LinkedHashMap<>();


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
                    if (key instanceof  PrivateKey) {
                        Certificate cert = keyStore.getCertificate(alias);
                        PublicKey publicKey = cert.getPublicKey();
                        keyMap.put(alias, new KeyPair(publicKey, (PrivateKey)key));

                    }




                } catch (UnrecoverableKeyException e) {
                    e.printStackTrace();
                }
            }
            return  keyMap;
        } catch (Exception e) {
            log.fatal(e.getMessage());

            return null;
        }

    }
}
