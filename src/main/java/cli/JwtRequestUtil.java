package cli;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.text.MessageFormat;
import java.util.HashMap;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.lang.JoseException;
import org.springframework.security.crypto.codec.Base64;

import static cli.JwtKeyUtil.deriveKey;
import static cli.JwtKeyUtil.generateKey;
import static cli.JwtKeyUtil.getShaHash;
import static cli.JwtKeyUtil.urlEncode;

/**
 * {@code JwtRequestUtil}
 *
 * @author Indra Basak
 * @since 1/24/17
 */
public class JwtRequestUtil {

    public static String generateRequestToken(String issuer, String subject,
            String audience, String password, AlgorithmType algoType,
            JwtRequest req) throws JwtException {
        String[] tokens = issuer.split(":");
        if (tokens.length != 2 || !tokens[0].equals("sid")) {
            throw new RuntimeException(MessageFormat.format(
                    "Cannot extract subscriber ID from issuer {0}; expected format: “sid:$subscriberId”",
                    issuer));
        }

        String subscriberId = tokens[1];

        Key key = generateKey(algoType, subscriberId, subject, password);
        JwtClaims claims = new JwtClaims();

        claims.setIssuer(issuer);
        claims.setSubject(subject);
        claims.setAudience(audience);
        claims.setExpirationTimeMinutesInTheFuture(5);
        claims.setNotBeforeMinutesInThePast(2);
        claims.setIssuedAtToNow();
        claims.setGeneratedJwtId();

        ObjectMapper mapper = new ObjectMapper();
        String regJson = null;
        try {
            regJson = mapper.writeValueAsString(processRequest(req));
        } catch (JsonProcessingException e) {
            throw new JwtException("Failed to serialize request.", e);
        }
        claims.setClaim("request", regJson);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key);
        //jws.setKeyIdHeaderValue(key.getKeyId());
        switch (algoType) {
            case SHA384:
                jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA384);
                break;
            case SHA512:
                jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA512);
                break;
            default:
                jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        }
        jws.setHeader(HeaderParameterNames.TYPE, "JWT");

        String jwt = null;
        try {
            jwt = jws.getCompactSerialization();
        } catch (JoseException e) {
            throw new JwtException("Failed to serialise JWT token.", e);
        }

        return jwt;
    }

    public static void parseRequestToken(String jwt,
            String passwordHash, String expectedAudience) throws JwtException {
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setExpectedAudience(expectedAudience)
                .setRequireExpirationTime()
                .setSkipSignatureVerification()
                .build();

        JwtContext context = null;
        try {
            context = jwtConsumer.process(jwt);
        } catch (InvalidJwtException e) {
            new JwtException("Invalid JWT token.", e);
        }

        JsonWebStructure joseObject = context.getJoseObjects().get(0);
        if (joseObject instanceof JsonWebSignature) {
            System.out.println("** " + joseObject);
            System.out.println(
                    "expected key " + ((JsonWebSignature) joseObject).getEncodedSignature());
        }
        String alg = joseObject.getHeaders().getStringHeaderValue(
                HeaderParameterNames.ALGORITHM);

        AlgorithmType algoType = JwtKeyUtil.getAlgorithmType(alg);

        String subscriberId;
        try {
            String issuer = context.getJwtClaims().getIssuer();
            String[] tokens = issuer.split(":");

            if (tokens.length != 2 || !tokens[0].equals("sid")) {
                throw new RuntimeException(MessageFormat.format(
                        "Cannot extract subscriber ID from issuer {0}; expected format: “sid:$subscriberId”",
                        issuer));
            }
            subscriberId = tokens[1];
            System.out.println("subscriber Id: " + subscriberId);
        } catch (MalformedClaimException e) {
            throw new JwtException("Failed to validate issuer.", e);
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


        JwtRequest request = parseRequest(context.getJwtClaims());
        assert request.getMeth() != null;
        assert request.getPath() != null;

        //need to validate request object
        validateSignature(algoType, jwt, subscriberId, subject, passwordHash);
    }

    public static void validateSignature(AlgorithmType algoType, String jwt,
            String subscriberId, String user,
            String passwordHash) throws JwtException {
        try {
            Key key = deriveKey(algoType, subscriberId, user, passwordHash);
            System.out.println("key: " + new String(key.getEncoded()));

            JwtConsumer consumer = new JwtConsumerBuilder()
                    .setSkipAllValidators()
                    .setVerificationKey(key)
                    .build();
            consumer.process(jwt);
        } catch (InvalidJwtException e) {
            throw new JwtException("Failed to validate JWT signature.", e);
        }
    }


    private static JwtRequest processRequest(
            JwtRequest request) throws JwtException {
        JwtRequest req = new JwtRequest();

        if (request.getBody() != null) {
            try {
                byte[] content = request.getBody().getBytes("UTF-8");
                byte[] hash = getShaHash(AlgorithmType.SHA256, content);
                String encodedHash = new String(Base64.encode(hash));
                req.setHash(encodedHash);
                req.setFunc(AlgorithmType.SHA256.name());
            } catch (UnsupportedEncodingException e) {
                throw new JwtException("Failed to create request body hash.",
                        e);
            }
        }

        req.setMeth(request.getMeth());
        req.setPath(urlEncode(request.getPath()));
        req.setQuery(urlEncode(request.getQuery()));

        return req;
    }

    private static JwtRequest parseRequest(JwtClaims claims) {
        JwtRequest request = null;
        Object requestObj = claims.getClaimValue("request");
        System.out.println("&&&&& " + claims.getClaimValue("request"));
        if (requestObj instanceof HashMap) {
            HashMap<String, Object> map = (HashMap) requestObj;
            request = new JwtRequest();
            request.setMeth((String) map.get("meth"));
            request.setPath((String) map.get("path"));
            request.setQuery((String) map.get("query"));
            request.setFunc((String) map.get("func"));
            request.setHash((String) map.get("hash"));
            //ObjectMapper mapper = new ObjectMapper();
            //Request request = mapper.readValue((String) requestObj, Request.class);
            System.out.println(request);
        }

        return request;
    }

}
