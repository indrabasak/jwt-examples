package jose4j;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.jose4j.jwk.RsaJsonWebKey;
import org.jose4j.jwk.RsaJwkGenerator;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;

/**
 * {@code Jose4jExample2}
 *
 * @author Indra Basak
 * @since 1/10/17
 */
public class Jose4jExample2 {

    /*
    {
    "iss": "sid:80042",
    "sub": "OLTP",
    "aud": "ctd",
    "exp": 1479255812,
    "nbf": 1479255802,
    "iat": 1479255792,
    "jti": "0814c961-6b27-4b88-b25b-654cb011d92b",
    "request": {
        "meth": "POST",
        "path": "/auth/org/80042/events/",
        "func": "S256",
        "hash": "99941f3cd43c3642f8f2151d2ca39c82310595ca343c182499ac50c0c8ad0215"
    }
}
     */
    @Data
    @NoArgsConstructor
    public static class Request {

        /*
        "meth": "POST",
        "path": "/auth/org/80042/events/",
        "func": "S256",
        "hash": "99941f3cd43c3642f8f2151d2ca39c82310595ca343c182499ac50c0c8ad0215"
         */

        private String method;

        private String path;

        private String algorithm;

        private String body;
    }


    private String createJWT(
            RsaJsonWebKey key) throws JoseException, JsonProcessingException {

        // Create the Claims, which will be the content of the JWT
        JwtClaims claims = new JwtClaims();

        // who creates the token and signs it
        claims.setIssuer("sid:80042");
        // the subject/principal is whom the token is about
        claims.setSubject("OLTP");
        // to whom the token is intended to be sent
        claims.setAudience("ctd");
        // time when the token will expire (10 minutes from now)
        claims.setExpirationTimeMinutesInTheFuture(10);
        // time before which the token is not yet valid (2 minutes ago)
        claims.setNotBeforeMinutesInThePast(2);
        // when the token was issued/created (now)
        claims.setIssuedAtToNow();
        // a unique identifier for the token
        claims.setGeneratedJwtId();

        Request req = new Request();
        req.setMethod("POST");
        req.setPath("/auth/org/80042/events/");
        req.setAlgorithm("S256");
        req.setBody(
                "99941f3cd43c3642f8f2151d2ca39c82310595ca343c182499ac50c0c8ad0215");

        ObjectMapper mapper = new ObjectMapper();

        //Object to JSON in String
        String regJson = mapper.writeValueAsString(req);

        // additional claims/attributes about the subject can be added
        claims.setClaim("request", regJson);

        // A JWT is a JWS and/or a JWE with JSON claims as the payload.
        // In this example it is a JWS so we create a JsonWebSignature object.
        JsonWebSignature jws = new JsonWebSignature();


        // The payload of the JWS is JSON content of the JWT Claims
        jws.setPayload(claims.toJson());

        // The JWT is signed using the private key
        jws.setKey(key.getPrivateKey());

        // Set the Key ID (kid) header because it's just the polite thing to do.
        // We only have one key in this example but a using a Key ID helps
        // facilitate a smooth key rollover process
        jws.setKeyIdHeaderValue(key.getKeyId());

        // Set the signature algorithm on the JWT/JWS that will integrity protect the claims
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);

        System.out.println("*** " + jws);
        //System.out.println("*** " + jws.get);

        // Sign the JWS and produce the compact serialization or the complete JWT/JWS
        // representation, which is a string consisting of three dot ('.') separated
        // base64url-encoded parts in the form Header.Payload.Signature
        // If you wanted to encrypt it, you can simply set this jwt as the payload
        // of a JsonWebEncryption object and set the cty (Content Type) header to "jwt".
        String jwt = jws.getCompactSerialization();


        // Now you can do something with the JWT. Like send it to some other party
        // over the clouds and through the interwebs.
        System.out.println("JWT: " + jwt);
        return jwt;
    }

    private void parseJWT(String jwt, RsaJsonWebKey key) {
        // Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
        // be used to validate and process the JWT.
        // The specific validation requirements for a JWT are context dependent, however,
        // it typically advisable to require a (reasonable) expiration time, a trusted issuer, and
        // and audience that identifies your system as the intended recipient.
        // If the JWT is encrypted too, you need only provide a decryption key or
        // decryption key resolver to the builder.
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                //                .setRequireExpirationTime() // the JWT must have an expiration time
                //                .setMaxFutureValidityInMinutes(
                //                        300) // but the  expiration time can't be too crazy
                //                .setAllowedClockSkewInSeconds(
                //                        30) // allow some leeway in validating time based claims to account for clock skew
                //                .setRequireSubject() // the JWT must have a subject claim
                //                .setExpectedIssuer(
                //                        "Issuer") // whom the JWT needs to have been issued by
                .setExpectedAudience("ctd") // to whom the JWT is intended for
                .setVerificationKey(
                        key.getKey()) // verify the signature with the public key
                .build(); // create the JwtConsumer instance

        try {
            //  Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            System.out.println("JWT validation succeeded! " + jwtClaims);
        } catch (InvalidJwtException e) {
            // InvalidJwtException will be thrown, if the JWT failed processing or validation in anyway.
            // Hopefully with meaningful explanations(s) about what went wrong.
            System.out.println("Invalid JWT! " + e);
        }
    }

    public RsaJsonWebKey createKey() throws JoseException {
        // Generate an RSA key pair, which will be used for signing and verification of the JWT, wrapped in a JWK
        RsaJsonWebKey rsaJsonWebKey = RsaJwkGenerator.generateJwk(2048);
        // Give the JWK a Key ID (kid), which is just the polite thing to do
        rsaJsonWebKey.setKeyId("k1");

        return rsaJsonWebKey;
    }

    public String creatKey2() {

        return null;
    }

    public static void main(
            String[] args) throws JoseException, JsonProcessingException {
        Jose4jExample2 ex = new Jose4jExample2();
        RsaJsonWebKey key = ex.createKey();
        String jwt = ex.createJWT(key);
        System.out.println("11111111111111111111");
        System.out.println(jwt);
        System.out.println("22222222222222222222");
        ex.parseJWT(jwt, key);
    }
}
