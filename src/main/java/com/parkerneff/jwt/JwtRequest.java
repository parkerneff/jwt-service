package com.parkerneff.jwt;


import lombok.Getter;
import lombok.Setter;

import java.util.Map;

public class JwtRequest {
    @Getter @Setter private String subject;
    @Getter @Setter private String client;
    @Getter @Setter private String[] roles;
    @Getter @Setter private Map<String, String> customClaims = null;


}
