package com.parkerneff.jwt;

import org.apache.commons.io.IOUtils;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.lang.JoseException;

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

public class KeyService {


    public PrivateKey privateKey() {

        try {
            String privateKeyPEM = IOUtils.resourceToString("private-pkcs8.pem", StandardCharsets.UTF_8, this.getClass().getClassLoader());

            // String privateKeyPEM = FileUtils.readFileToString(new File("private-pkcs8.pem"), StandardCharsets.UTF_8);


            // strip of header, footer, newlines, whitespaces
            privateKeyPEM = privateKeyPEM
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            // decode to get the binary DER representation
            byte[] privateKeyDER = Base64.getDecoder().decode(privateKeyPEM);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyDER));
            return privateKey;

        } catch (IOException e1) {
            e1.printStackTrace();
        } catch (InvalidKeySpecException e) {


        } catch (NoSuchAlgorithmException e) {

            return null;
        }
        return null;
    }


    public PublicKey getPublicKey() {

        try {
            String publicKeyPEM = IOUtils.resourceToString("public.pem", StandardCharsets.UTF_8, this.getClass().getClassLoader());


            // strip of header, footer, newlines, whitespaces
            publicKeyPEM = publicKeyPEM
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            // decode to get the binary DER representation
            byte[] publicKeyDER = Base64.getDecoder().decode(publicKeyPEM);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyDER));

            try {
                RsaJsonWebKey rsaJwk = (RsaJsonWebKey) PublicJsonWebKey.Factory.newPublicJwk(publicKey);
                rsaJwk.setKeyId("k1");
            } catch (JoseException e) {
                e.printStackTrace();
            }
            return publicKey;

        } catch (IOException e1) {
            e1.printStackTrace();
        } catch (InvalidKeySpecException e) {


        } catch (NoSuchAlgorithmException e) {

            return null;
        }
        return null;
    }
    public JsonWebKeySet getJsonWebKeySet() {

        try {
            String publicKeyPEM = IOUtils.resourceToString("public.pem", StandardCharsets.UTF_8, this.getClass().getClassLoader());


            // strip of header, footer, newlines, whitespaces
            publicKeyPEM = publicKeyPEM
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            // decode to get the binary DER representation
            byte[] publicKeyDER = Base64.getDecoder().decode(publicKeyPEM);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyDER));


            RsaJsonWebKey rsaJwk = (RsaJsonWebKey) PublicJsonWebKey.Factory.newPublicJwk(publicKey);
            rsaJwk.setKeyId("k1");

            JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(rsaJwk);


            return jsonWebKeySet;


        } catch (Exception e) {
            return null;
        }

    }
}
