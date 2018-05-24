package jose4j;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.text.MessageFormat;
import java.util.LinkedList;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringEscapeUtils;
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
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;

/**
 * {@code Jose4jExample3}
 *
 * @author Indra Basak
 * @since 1/11/17
 */
public class Jose4jExample3 {

    public enum AlgoType {
        SHA256, SHA384, SHA512
    }

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


    private String createJWT(String issuer, String subject, String audience,
            String password) throws JoseException, JsonProcessingException, UnsupportedEncodingException {

        Key key = createSha256Key(issuer, subject, password);
        // Create the Claims, which will be the content of the JWT
        JwtClaims claims = new JwtClaims();

        claims.setIssuer("sid:" + issuer);
        claims.setSubject(subject);
        claims.setAudience(audience);
        claims.setExpirationTimeMinutesInTheFuture(10);
        claims.setNotBeforeMinutesInThePast(2);
        claims.setIssuedAtToNow();
        claims.setGeneratedJwtId();

        Jose4jExample2.Request req = new Jose4jExample2.Request();
        req.setMethod("POST");
        req.setPath("/auth/org/80042/events/");
        req.setAlgorithm("S256");
        req.setBody(
                "99941f3cd43c3642f8f2151d2ca39c82310595ca343c182499ac50c0c8ad0215");

        ObjectMapper mapper = new ObjectMapper();
        String regJson = mapper.writeValueAsString(req);
        claims.setClaim("request", regJson);

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key);
        //jws.setKeyIdHeaderValue(key.getKeyId());
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
        jws.setHeader(HeaderParameterNames.TYPE, "JWT");
        jws.setKeyIdHeaderValue("ae873fcd109");


        System.out.println("*** " + jws);
        //System.out.println("*** " + jws.get);

        String jwt = jws.getCompactSerialization();

        System.out.println("JWT: " + jwt);
        return jwt;
    }

    private void parseJWTx(String jwt,
            String password) throws InvalidJwtException, MalformedClaimException, UnsupportedEncodingException {
        String[] tokens = jwt.split("\\.");

        if (tokens.length != 3) {
            throw new RuntimeException(MessageFormat.format(
                    "Invalid JWT token {0}; expected format: “header.payload.signature”",
                    jwt));
        }

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setExpectedAudience("ctd")
                .setSkipSignatureVerification()
                .setSkipAllValidators()
                .build();

        JwtContext context = jwtConsumer.process(jwt);
        JsonWebStructure joseObject = context.getJoseObjects().get(0);
        if (joseObject instanceof JsonWebSignature) {
            System.out.println("** " + joseObject);
            System.out.println(
                    "expected key " + ((JsonWebSignature) joseObject).getEncodedSignature());
        }
        String alg = joseObject.getHeaders().getStringHeaderValue(
                HeaderParameterNames.ALGORITHM);


        System.out.println("alg: " + alg);
        AlgoType algoType = getAlgoType(alg);
        System.out.println(algoType);

        String issuer = context.getJwtClaims().getIssuer();
        tokens = issuer.split(":");

        if (tokens.length != 2 || !tokens[0].equals("sid")) {
            throw new RuntimeException(MessageFormat.format(
                    "Cannot extract subscriber ID from issuer {0}; expected format: “sid:$subscriberId”",
                    issuer));
        }

        String subscriberId = tokens[1];
        System.out.println("subscriber Id: " + subscriberId);

        String subject = context.getJwtClaims().getSubject();
        System.out.println("subject: " + subject);
        // Make sure we have a subject.
        if (subject == null || subject.trim().isEmpty()) {
            throw new RuntimeException(
                    "No username specified in the subject");
        }

        Key key = createShaKey(algoType, subscriberId, subject, password);
        System.out.println("key: " + new String(key.getEncoded()));

        jwtConsumer = new JwtConsumerBuilder()
                .setExpectedAudience("ctd")
                .setVerificationKey(key)
                .build();

        jwtConsumer.process(jwt);
        jwtConsumer.processToClaims(jwt);

    }

    private void parseJWT(String jwt,
            String password) throws UnsupportedEncodingException {
        try {
            JwtClaims claims = processJWT(jwt);
            System.out.println("JWT validation succeeded! " + claims);
            String issuer = claims.getIssuer();
            System.out.println(issuer);
            String[] tokens = issuer.split(":");

            if (tokens.length != 2 || !tokens[0].equals("sid")) {
                throw new RuntimeException(MessageFormat.format(
                        "Cannot extract subscriber ID from issuer {0}; expected format: “sid:$subscriberId”",
                        issuer));
            }

            String subscriberId = tokens[1];

            String subject = claims.getSubject();
            // Make sure we have a subject.
            if (subject == null || subject.trim().isEmpty()) {
                throw new RuntimeException(
                        "No username specified in the subject");
            }

            Key key = createSha256Key(subscriberId, subject, password);

            JwtConsumer consumer = new JwtConsumerBuilder()
                    .setExpectedAudience("ctd")
                    .setVerificationKey(key)
                    .build();


        } catch (InvalidJwtException e) {
            System.out.println("Invalid JWT! " + e);
        } catch (MalformedClaimException e) {
            e.printStackTrace();
        }
    }

    private void parseToken(String jwt,
            String password) throws JoseException, InvalidJwtException {

        String[] tokens = jwt.split(".");
        if (tokens.length != 3) {
            throw new InvalidJwtException(
                    "Invalid JWT as it should have 3 parts separated by '.'");
        }


        JsonWebStructure joseObject =
                JsonWebStructure.fromCompactSerialization(jwt);

        if (!(joseObject instanceof JsonWebSignature)) {
            throw new InvalidJwtException("Invalid JWT");
        }

        String alg = joseObject.getHeaders().getStringHeaderValue(
                HeaderParameterNames.ALGORITHM);

        AlgoType algoType = getAlgoType(alg);


    }

    private AlgoType getAlgoType(String alg) throws InvalidJwtException {

        AlgoType algoType = null;

        if (alg == null) {
            throw new InvalidJwtException("Null hash algorithm");
        }

        switch (alg.toUpperCase()) {
            case AlgorithmIdentifiers.HMAC_SHA256:
            case "S256":
            case "SHA256":
                algoType = AlgoType.SHA256;
                break;
            case AlgorithmIdentifiers.HMAC_SHA384:
            case "S384":
            case "SHA384":
                algoType = AlgoType.SHA384;
                break;
            case AlgorithmIdentifiers.HMAC_SHA512:
            case "S512":
            case "SHA512":
                algoType = AlgoType.SHA384;
                break;
            default:
                throw new InvalidJwtException("Unknown hash algorithm " + alg);
        }

        return algoType;
    }

    private JwtClaims processJWT(String jwt) throws InvalidJwtException {
        JwtClaims jwtClaims = null;
        LinkedList<JsonWebStructure> joseObjects = new LinkedList<>();

        while (jwtClaims == null) {
            try {
                JsonWebStructure joseObject =
                        JsonWebStructure.fromCompactSerialization(jwt);

                String payload = null;
                if (joseObject instanceof JsonWebSignature) {
                    JsonWebSignature jws = (JsonWebSignature) joseObject;
                    payload = jws.getUnverifiedPayload();
                    System.out.println(
                            "&&&&&&&&&&&&&&&&&&&&& " + jws.getAlgorithm());

                    System.out.println(
                            "&&&&&&&&&&&&&&&&&&&&& " + jws.getHeaders().getFullHeaderAsJsonString());
                } else {

                }

                System.out.println("&&&&&&&&&&&&&&&&&&&&& " + payload);

                jwtClaims = JwtClaims.parse(payload);
            } catch (JoseException e) {
                e.printStackTrace();
            }
        }

        return jwtClaims;
    }

    public Key createSha256Key(String subscriberId, String user,
            String password) throws UnsupportedEncodingException {

        return createShaKey(AlgoType.SHA256, subscriberId, user, password);
    }

    public Key createShaKey(AlgoType algo, String subscriberId, String user,
            String password) throws UnsupportedEncodingException {
        //SHA256($subscriber_id + "/" + $sub + ":" + SHA256($subscriber_id + $password))
        //HMAC_SHA256
        String subIdPwd = String.format("%1$s%2$s", subscriberId, password);
        System.out.println("Hello1: " + subIdPwd);
        subIdPwd = StringEscapeUtils.escapeHtml3(subIdPwd);
        System.out.println("Hello2: " + subIdPwd);
        String subIdPwdHash = getShaHash(algo, subIdPwd);
        System.out.println("Hello3: " + subIdPwdHash);
        //String hash = StringEscapeUtils.escapeHtml3(subIdPwdHash);
        //String hash = subIdPwdHash;
        String subIdUserPwd =
                String.format("%1$s/%2$s:%3$s", subscriberId, user,
                        subIdPwdHash);
        System.out.println("Hello4a: " + subIdUserPwd);
        subIdUserPwd = new String(concatenateByteArrays(
                String.format("%1$s/%2$s:", subscriberId, user).getBytes(
                        "UTF-8"), subIdPwdHash.getBytes("UTF-8")));
        System.out.println("Hello4b: " + subIdUserPwd);
        String subIdUserPwdHash = getShaHash(algo, subIdUserPwd);
        System.out.println("Hello5: " + subIdUserPwdHash);
        //byte[] keybyte = subIdUserPwdHash.getBytes("UTF-8");
        //System.out.println("Hello6: " + new String(Base64.encode(keybyte)));
        Key key = new HmacKey(subIdUserPwdHash.getBytes("UTF-8"));

        return key;
    }

    private byte[] concatenateByteArrays(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    public String getShaHash(AlgoType algo, String data)
            throws UnsupportedEncodingException {
        String hash;

        switch (algo) {
            case SHA384:
                hash = DigestUtils.sha384Hex(data);
                break;
            case SHA512:
                hash = DigestUtils.sha512Hex(data);
                break;
            default:
                hash = DigestUtils.sha256Hex(data);
        }

        return hash;
    }

    public void test1() throws UnsupportedEncodingException, JoseException, JsonProcessingException {
        String jwt = createJWT("80042", "OLTP", "ctd", "abcd1234");
        System.out.println("11111111111111111111");
        System.out.println(jwt);
        System.out.println("22222222222222222222");
        parseJWT(jwt, "abcd1234");
        //ex.parseRequestToken(jwt, "hello");
    }

    public void test2() throws UnsupportedEncodingException, JoseException, JsonProcessingException, InvalidJwtException {
        String jwt = createJWT("80042", "OLTP", "ctd", "abcd1234");
        System.out.println("11111111111111111111");
        System.out.println(jwt);
        System.out.println("22222222222222222222");
        parseToken(jwt, "abcd1234");
    }

    public void test3() throws UnsupportedEncodingException, JoseException, JsonProcessingException, MalformedClaimException, InvalidJwtException {
        String jwt = createJWT("80042", "OLTP", "ctd", "abcd1234");
        System.out.println("11111111111111111111");
        System.out.println(jwt);
        System.out.println("22222222222222222222");
        parseJWTx(jwt, "abcd1234");
    }

    public void test4() throws UnsupportedEncodingException, MalformedClaimException, InvalidJwtException {
        String jwt =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjdGQiLCJleHAiOjE0ODQzNTY1NTgsImlhdCI6MTQ4NDM1NjI1OCwiaXNzIjoic2lkOjgwMDQyIiwianRpIjoiYThjOTcyNWUtZjBjMS00NTlhLTg0YmItY2MxNjhjZTJmYjVhIiwicmVxdWVzdCI6eyJtZXRoIjoiR0VUIiwicGF0aCI6Ii9mb28vYmFyIn0sInN1YiI6Ik9MVFAifQ.-hFv5u52P5ApLTtjGlVZGUlt9JWoJ6PFUlagxoQhses";

        String jwt2 =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjYXAiLCJleHAiOjE0ODQzNjY1MjQsImlhdCI6MTQ4NDM2NjIyNCwiaXNzIjoic2lkOjgwMDQyIiwianRpIjoiOGVhMjk5NWQtMWY4NS00YTRmLTk3NjEtNGU4YjhjYjhkODRhIiwicmVxdWVzdCI6eyJtZXRoIjoiR0VUIiwicGF0aCI6Ii9mb28vYmFyIn0sInN1YiI6Ik9MVFAifQ.B4GN-CRgOdt2-YEzjtX06BZWOd1TbWmrn49LFUNKN6g";
        parseJWTx(jwt2, "abcd1234");
    }

    public static void main(
            String[] args) throws JoseException, JsonProcessingException, UnsupportedEncodingException, InvalidJwtException, MalformedClaimException {
        Jose4jExample3 ex = new Jose4jExample3();
        //ex.test3();
        ex.test4();
        //ex.test1();
        //ex.createShaKey(AlgoType.SHA256, "80042", "OLTP",
        //        "abcd1234");
    }
}
