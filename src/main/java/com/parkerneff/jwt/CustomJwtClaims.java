package com.parkerneff.jwt;

import org.jose4j.jwt.JwtClaims;

import java.util.Map;

public class CustomJwtClaims extends JwtClaims {
    public void setCustomClaims(Map<String, String> customClaims) {

        if (customClaims != null) {
            for (String key : customClaims.keySet()) {
                this.setStringClaim(key, customClaims.get(key));
            }

        }

    }
}
