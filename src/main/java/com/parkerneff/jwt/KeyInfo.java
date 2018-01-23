package com.parkerneff.jwt;

import lombok.Getter;
import lombok.Setter;
import org.jose4j.jwk.JsonWebKeySet;

import java.security.PrivateKey;
import java.util.Map;

public class KeyInfo {
    @Getter @Setter private JsonWebKeySet jsonWebKeySet;
    @Getter @Setter private Map<String, PrivateKey> privateKeyMap;
    public KeyInfo(JsonWebKeySet jsonWebKeySet, Map<String, PrivateKey> privateKeyMap) {
        this.jsonWebKeySet = jsonWebKeySet;
        this.privateKeyMap = privateKeyMap;
    }
}
