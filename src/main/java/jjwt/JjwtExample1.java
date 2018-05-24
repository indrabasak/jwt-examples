package jjwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 * {@code JjwtExample1}
 *
 * @author Indra Basak
 * @since 1/3/17
 */
public class JjwtExample1 {
    //Sample method to construct a JWT
    private String createJWT(String id, String issuer, String subject,
            long ttlMillis, String apiKey) {

        //The JWT signature algorithm we will be using to sign the token
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        //We will sign our JWT with our ApiKey secret
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(apiKey);
        Key signingKey = new SecretKeySpec(apiKeySecretBytes,
                signatureAlgorithm.getJcaName());

        //Let's set the JWT Claims
        JwtBuilder builder = Jwts.builder().setId(id)
                .setIssuedAt(now)
                .setSubject(subject)
                .setIssuer(issuer)
                .signWith(signatureAlgorithm, signingKey);

        //if it has been specified, let's add the expiration
        if (ttlMillis >= 0) {
            long expMillis = nowMillis + ttlMillis;
            Date exp = new Date(expMillis);
            builder.setExpiration(exp);
        }

        //Builds the JWT and serializes it to a compact, URL-safe string
        System.out.println(builder);
        return builder.compact();
    }

    //Sample method to validate and read the JWT
    private void parseJWT(String jwt, String apiKey) {

        //This line will throw an exception if it is not a signed JWS (as expected)
        Claims claims = Jwts.parser()
                .setSigningKey(DatatypeConverter.parseBase64Binary(apiKey))
                .parseClaimsJws(jwt).getBody();
        System.out.println(claims);
        System.out.println("ID: " + claims.getId());
        System.out.println("Subject: " + claims.getSubject());
        System.out.println("Issuer: " + claims.getIssuer());
        System.out.println("Expiration: " + claims.getExpiration());
    }

    //Launch Key - Adam - contact
    private String createKey() {
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

    public static void main(String[] args) {
        JjwtExample1 ex = new JjwtExample1();
        String encodedKey = ex.createKey();
        String jwt = ex.createJWT("indra-id", "indra", "jwt-test",
                new Date().getTime(), encodedKey);
        System.out.println(jwt);
        ex.parseJWT(jwt, encodedKey);
    }
}
