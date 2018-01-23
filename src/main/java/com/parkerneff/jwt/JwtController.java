package com.parkerneff.jwt;


import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.PrivateKey;


@RestController
public class JwtController {
    // https://connect2id.com/products/nimbus-jose-jwt/examples/jwt-with-rsa-signature
// https://github.com/jwtk/jjwt
    @Autowired
    private PrivateKey privateKey;

    @Autowired
    private JsonWebKeySet jsonWebKeySet;

    @RequestMapping(value = "/token", method = RequestMethod.POST)
    public String generateToken(@RequestBody JwtRequest jwtRequest) {


        try {



            // Create the Claims, which will be the content of the JWT
            JwtClaims claims = new JwtClaims();
            claims.setIssuer("parker-idp");  // who creates the token and signs it
            claims.setAudience("Audience"); // to whom the token is intended to be sent
            claims.setExpirationTimeMinutesInTheFuture(60); // time when the token will expire (10 minutes from now)
            claims.setGeneratedJwtId(); // a unique identifier for the token
            claims.setIssuedAtToNow();  // when the token was issued/created (now)
            claims.setNotBeforeMinutesInThePast(2); // time before which the token is not yet valid (2 minutes ago)
            claims.setSubject(jwtRequest.getSubject()); // the subject/principal is whom the token is about


            claims.setStringListClaim("groups", jwtRequest.getRoles()); // multi-valued claims work too and will end up as a JSON array

            // A JWT is a JWS and/or a JWE with JSON claims as the payload.
            // In this example it is a JWS so we create a JsonWebSignature object.
            JsonWebSignature jws = new JsonWebSignature();

            // The payload of the JWS is JSON content of the JWT Claims
            jws.setPayload(claims.toJson());

            // The JWT is signed using the private key
            jws.setKey(privateKey);

            // Set the Key ID (kid) header because it's just the polite thing to do.
            // We only have one key in this example but a using a Key ID helps
            // facilitate a smooth key rollover process
        //    jws.setKeyIdHeaderValue(rsaJsonWebKey.getKeyId());

            // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
            jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

            // Sign the JWS and produce the compact serialization or the complete JWT/JWS
            // representation, which is a string consisting of three dot ('.') separated
            // base64url-encoded parts in the form Header.Payload.Signature
            // If you wanted to encrypt it, you can simply set this jwt as the payload
            // of a JsonWebEncryption object and set the cty (Content Type) header to "jwt".
            String jwt = jws.getCompactSerialization();
            return jwt;

        } catch (JoseException e) {
            return e.getMessage();
        }




    }

    @RequestMapping("/jwks")
    public String getJwk() {
        return jsonWebKeySet.toJson();

    }

}
