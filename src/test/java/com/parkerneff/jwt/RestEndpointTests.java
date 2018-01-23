package com.parkerneff.jwt;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwk.HttpsJwks;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.resolvers.HttpsJwksVerificationKeyResolver;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.PublicKey;
import java.util.Map;

import static org.assertj.core.api.BDDAssertions.then;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

/**
 * Basic integration tests for service demo application.
 *
 * @author Dave Syer
 */
@RunWith(SpringRunner.class)
@SpringBootTest(classes = Application.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {"management.port=0"})
public class RestEndpointTests {
    @Value("${issuer}") String issuer;

    @LocalServerPort
    private int port;

    //@Value("${local.management.port}")
    //private int mgt;

    @Autowired
    private TestRestTemplate testRestTemplate;




    @Test
    public void testValidJwk() throws Exception {
        @SuppressWarnings("rawtypes")



        HttpsJwks httpsJkws = new HttpsJwks("http://localhost:" + this.port + "/jwks");
        HttpsJwksVerificationKeyResolver httpsJwksKeyResolver = new HttpsJwksVerificationKeyResolver(httpsJkws);

        JwtRequest jwtRequest = new JwtRequest();
        jwtRequest.setSubject("parkerneff");
        jwtRequest.setClient("testclient");


        jwtRequest.setRoles(new String[]{"admin", "user"});
        HttpEntity<JwtRequest> request = new HttpEntity<>(jwtRequest);
        String token = this.testRestTemplate.postForObject("http://localhost:" + this.port + "/token", request, String.class);
        System.out.println("TOKEN=" + token);
        assertNotNull(token);


        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime() // the JWT must have an expiration time
                .setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
                .setRequireSubject() // the JWT must have a subject claim
                .setExpectedIssuer(issuer) // whom the JWT needs to have been issued by
                .setExpectedAudience(jwtRequest.getClient()) // to whom the JWT is intended for
                .setVerificationKeyResolver(httpsJwksKeyResolver)
                .build(); // create the JwtConsumer instance

        try {
            JwtClaims jwtClaims = jwtConsumer.processToClaims(token);
        } catch (InvalidJwtException e) {
            fail(e.getMessage());
        }


    }
}
