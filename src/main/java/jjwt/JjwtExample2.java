package jjwt;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * {@code JjwtExample2}
 *
 * @author Indra Basak
 * @since 1/5/17
 */
public class JjwtExample2 {

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

    /*
    {
    "iss": "ten:80042",
    "sub": "80042/OLTP",
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
    public String createJWT(String apiKey) throws JsonProcessingException {

        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        long expMillis = nowMillis + 200000;
        Date exp = new Date(expMillis);

        //We will sign our JWT with our ApiKey secret
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(apiKey);
        Key
                signingKey = new SecretKeySpec(apiKeySecretBytes,
                signatureAlgorithm.getJcaName());

        Request req = new Request();
        req.setMethod("POST");
        req.setPath("/auth/org/80042/events/");
        req.setAlgorithm("S256");
        req.setBody(
                "99941f3cd43c3642f8f2151d2ca39c82310595ca343c182499ac50c0c8ad0215");

        ObjectMapper mapper = new ObjectMapper();

        //Object to JSON in String
        String regJson = mapper.writeValueAsString(req);

        /*
        {
  "typ": "JWT",
  "alg": "HS256",
  "kid": "ae873fcd109"
}
         */
        Header header = Jwts.header().setType("JWT");
        //Let's set the JWT Claims
        JwtBuilder builder = Jwts.builder()
                .setHeader((Map<String, Object>) header)
                .setHeaderParam("kid", "ae873fcd109")
                .setIssuer("sid:80042")
                .setSubject("OLTP")
                .setAudience("ctd")
                .setExpiration(exp)
                .setNotBefore(now)
                .setIssuedAt(now)
                .setId(UUID.randomUUID().toString())
                //.setPayload(regJson)
                .claim("request", regJson)
                .signWith(signatureAlgorithm, signingKey);

        //Builds the JWT and serializes it to a compact, URL-safe string
        System.out.println(builder);
        return builder.compact();
    }

    //Sample method to validate and read the JWT
    private void parseJWT(String jwt, String apiKey) {

        //This line will throw an exception if it is not a signed JWS (as expected)
        Jws<Claims> claims = Jwts.parser()
                .setSigningKey(DatatypeConverter.parseBase64Binary(apiKey))
                .parseClaimsJws(jwt);
        //        Claims claims = Jwts.parser()
        //                .setSigningKey(DatatypeConverter.parseBase64Binary(apiKey))
        //                .parseClaimsJws(jwt).getBody();

        System.out.println(claims);
        System.out.println("ID: " + claims.getBody().getId());
        System.out.println("Subject: " + claims.getBody().getSubject());
        System.out.println("Issuer: " + claims.getBody().getIssuer());
        System.out.println("Expiration: " + claims.getBody().getExpiration());
    }

    public String createKey() {
        String encodedKey = null;
        SecretKey secretKey = null;
        try {
            secretKey = KeyGenerator.getInstance("AES").generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        // get base64 encoded version of the key
        assert secretKey != null;
        try {
            encodedKey =
                    Base64.getEncoder().encodeToString(secretKey.getEncoded());
        } catch (NullPointerException e) {

        }

        return encodedKey;
    }

    public static void main(String[] args) throws JsonProcessingException {
        JjwtExample2 ex = new JjwtExample2();
        String encodedKey = ex.createKey();
        String jwt = ex.createJWT(encodedKey);
        System.out.println(jwt);
        ex.parseJWT(jwt, encodedKey);
    }
}
