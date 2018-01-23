package com.parkerneff.jwt;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.JwksVerificationKeyResolver;
import org.junit.Test;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class CustomJwtClaimsTest {


    @Test
    public void testGenerateJwt() {
        String testIssuer = "test.issuer";
        String subject = "mysubject";
        String audience = "myaudience";
        String[] roles = new String[]{"admin", "user"};
        Map<String, String> customClaims = new HashMap<>();
        customClaims.put("foo", "bar");
        customClaims.put("hello", "world");

        KeyPairService keyPairService = new KeyPairService();
        keyPairService.setKeyStorePassword("password");
        keyPairService.setKeyStoreFile("jwtkeys.jks");
        KeyInfo keyInfo = keyPairService.getKeyInfo();


        TokenService tokenService = new TokenService();

        tokenService.setPrivateKeyMap(keyInfo.getPrivateKeyMap());

        tokenService.setIssuer(testIssuer);
        tokenService.setAudience(audience);

        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setSubject(subject);
        jwtRequest.setRoles(roles);


        jwtRequest.setCustomClaims(customClaims);



        String token = tokenService.generateToken(jwtRequest);


        JwksVerificationKeyResolver resolver = new JwksVerificationKeyResolver(keyInfo.getJsonWebKeySet().getJsonWebKeys());

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer(testIssuer) // whom the JWT needs to have been issued by
                .setExpectedAudience(audience) // to whom the JWT is intended for
                .setVerificationKeyResolver(resolver) // verify the signature with the public key
                .setJwsAlgorithmConstraints( // only allow the expected signature algorithm(s) in the given context
                        new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, // which is only RS256 here
                                AlgorithmIdentifiers.RSA_USING_SHA256))
                .build(); // create the JwtConsumer instance

        try {
            JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
            assertEquals(subject, jwtClaims.getSubject() );

            assertEquals(roles.length, jwtClaims.getStringListClaimValue("groups").size());
        } catch (Exception e) {
            fail(e.getMessage());
        }


    }
}
