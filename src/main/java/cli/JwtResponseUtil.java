package cli;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.text.MessageFormat;
import java.util.List;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.springframework.security.crypto.codec.Base64;

/**
 * {@code JwtResponseUtil}
 *
 * @author Indra Basak
 * @since 1/27/17
 */
public class JwtResponseUtil {

    public static final void parseResponseToken(String jwt,
            String password, Response expectedResponse) throws JwtException {
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setSkipSignatureVerification()
                .build();

        JwtContext context = null;
        try {
            context = jwtConsumer.process(jwt);
        } catch (InvalidJwtException e) {
            new JwtException("Invalid JWT token.", e);
        }
        /*
        claims.setIssuer(credentials.getAudience());
        claims.setSubject(credentials.getUser());
        claims.setAudience(
                ISSUER_IDENTIFIER + ":" + credentials.getSubscriberId());
        claims.setJwtId(credentials.getJwtId());
         */

        JsonWebStructure joseObject = context.getJoseObjects().get(0);
        if (joseObject instanceof JsonWebSignature) {
            System.out.println("** " + joseObject);
            System.out.println(
                    "expected key " + ((JsonWebSignature) joseObject).getEncodedSignature());
        }
        String alg = joseObject.getHeaders().getStringHeaderValue(
                HeaderParameterNames.ALGORITHM);

        AlgorithmType algoType = JwtKeyUtil.getAlgorithmType(alg);


        try {
            String issuer = context.getJwtClaims().getIssuer();
            assert issuer != null;
            System.out.println("issuer: " + issuer);
        } catch (MalformedClaimException e) {
            e.printStackTrace();
        }

        String subscriberId = null;
        try {
            List<String> audiences = context.getJwtClaims().getAudience();
            assert audiences.size() == 1;
            String audience = audiences.get(0);
            String[] tokens = audience.split(":");
            if (tokens.length != 2 || !tokens[0].equals("sid")) {
                throw new RuntimeException(MessageFormat.format(
                        "Cannot extract subscriber ID from issuer {0}; expected format: “sid:$subscriberId”",
                        audience));
            }
            subscriberId = tokens[1];
            System.out.println("subscriber Id: " + subscriberId);
        } catch (MalformedClaimException e) {
            throw new JwtException("Failed to validate audience.", e);
        }

        String subject;
        try {
            subject = context.getJwtClaims().getSubject();
            if (subject == null || subject.trim().isEmpty()) {
                throw new RuntimeException(
                        "No username specified in the subject");
            }
        } catch (MalformedClaimException e) {
            throw new JwtException("Failed to validate subject.", e);
        }
        System.out.println("subject: " + subject);

        try {
            JwtResponse response = parseResponse(context.getJwtClaims());
            validateResponse(expectedResponse, response);
            System.out.println(response);
        } catch (IOException e) {
            throw new JwtException("Failed to parse response", e);
        }

        Key key = JwtKeyUtil.generateKey(algoType, subscriberId, subject,
                password);

        //need to validate request object
        validateSignature(jwt, key);
    }

    public static void validateSignature(String jwt,
            Key key) throws JwtException {
        try {

            JwtConsumer consumer = new JwtConsumerBuilder()
                    .setSkipAllValidators()
                    .setVerificationKey(key)
                    .build();
            consumer.process(jwt);
        } catch (InvalidJwtException e) {
            throw new JwtException("Failed to validate JWT signature.", e);
        }
    }

    private static JwtResponse parseResponse(
            JwtClaims claims) throws IOException {
        JwtResponse response = null;
        Object responseObj = claims.getClaimValue("response");
        System.out.println(responseObj);
        if (responseObj instanceof String) {
            ObjectMapper mapper = new ObjectMapper();
            response =
                    mapper.readValue((String) responseObj, JwtResponse.class);
        }

        return response;
    }

    private static void validateResponse(Response response,
            JwtResponse jwtRsp) throws JwtException, UnsupportedEncodingException {
        if (response.getStatus() != jwtRsp.getStatus()) {
            String msg = MessageFormat.format(
                    "Expected response status {0} do not match response status {1} specified in JWT payload.",
                    response.getStatus(), jwtRsp.getStatus());
            throw new JwtException(msg);
        }

        if (response.getCache() != null && !response.getCache().equals(
                jwtRsp.getCache())) {
            String msg = MessageFormat.format(
                    "Expected response cache {0} do not match response cache {1} specified in JWT payload.",
                    response.getCache(), jwtRsp.getCache());
            throw new JwtException(msg);
        }

        if (response.getLocation() != null && !response.getLocation().equals(
                jwtRsp.getLocation())) {
            String msg = MessageFormat.format(
                    "Expected response location {0} do not match response location {1} specified in JWT payload.",
                    response.getLocation(), jwtRsp.getLocation());
            throw new JwtException(msg);
        }

        if (response.getBody() != null && jwtRsp.getHash() != null) {
            byte[] hash = JwtKeyUtil.getShaHash(AlgorithmType.SHA256,
                    response.getBody().getBytes("UTF-8"));
            String encodedHash = new String(Base64.encode(hash));
            if (!encodedHash.equals(jwtRsp.getHash())) {
                String msg = MessageFormat.format(
                        "Expected response hash {0} do not match response hash {1} specified in JWT payload.",
                        encodedHash, jwtRsp.getHash());
                throw new JwtException(msg);
            }
        }
    }

    @Data
    @NoArgsConstructor
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private static class JwtResponse {
        //response status code
        private int status;

        //same value as the 'Cache-Control' header, if any
        private String cache;

        //Same value as the Location header, if any
        private String location;

        //cryptographic hash function used to generate the hash digest of
        //the response body (if present)
        private String func;

        //Base64-encoded hash digest of the response body (if present) using
        //the algorithm specified by the func key.
        private String hash;
    }
}
