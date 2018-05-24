package jose4j;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Key;
import java.text.MessageFormat;
import java.util.HashMap;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
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
 * {@code Jose4jExample4}
 *
 * @author Indra Basak
 * @since 1/16/17
 */
public class Jose4jExample4 {

    public enum AlgoType {
        SHA256, SHA384, SHA512
    }

    //iss sid:80042 --sub OLTP -p abcd1234 --aud ctd http://localhost:8192/foo/bar

    private String generateRequestToken(String issuer, String subject,
            String audience, String password, AlgoType algoType,
            Request req) throws UnsupportedEncodingException, JsonProcessingException, JoseException {
        String[] tokens = issuer.split(":");
        if (tokens.length != 2 || !tokens[0].equals("sid")) {
            throw new RuntimeException(MessageFormat.format(
                    "Cannot extract subscriber ID from issuer {0}; expected format: “sid:$subscriberId”",
                    issuer));
        }

        String subscriberId = tokens[1];

        Key key = generateKey(algoType, subscriberId, subject, password);
        //TODO needs to be fixed - subId is 0 due to bug in admin UI
        //Key key = generateKey(algoType, "0", subject, password);
        // Create the Claims, which will be the content of the JWT
        JwtClaims claims = new JwtClaims();

        claims.setIssuer(issuer);
        claims.setSubject(subject);
        claims.setAudience(audience);
        claims.setExpirationTimeMinutesInTheFuture(5);
        claims.setNotBeforeMinutesInThePast(2);
        claims.setIssuedAtToNow();
        claims.setGeneratedJwtId();

        ObjectMapper mapper = new ObjectMapper();
        String regJson = mapper.writeValueAsString(req);
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


        System.out.println("*** " + jws);
        //System.out.println("*** " + jws.get);

        String jwt = jws.getCompactSerialization();

        return jwt;
    }

    private void parseToken(String jwt,
            String passwordHash,
            String expectedAudience) throws InvalidJwtException, MalformedClaimException, IOException, DecoderException {
        String[] tokens = jwt.split("\\.");

        if (tokens.length != 3) {
            throw new RuntimeException(MessageFormat.format(
                    "Invalid JWT token {0}; expected format: “header.payload.signature”",
                    jwt));
        }

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                //.setExpectedAudience("ctd")
                .setExpectedAudience(expectedAudience)
                .setRequireExpirationTime()
                //.setMaxFutureValidityInMinutes(10)
                //.setAllowedClockSkewInSeconds(30)
                .setSkipSignatureVerification()
                //.setSkipAllValidators()
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

        getRequest(context.getJwtClaims());

        //Key key = deriveKey(algoType, subscriberId, subject, password);
        //        Key key = deriveKey(algoType, "0", subject, password);
        //        System.out.println("key: " + new String(key.getEncoded()));
        //
        //        jwtConsumer = new JwtConsumerBuilder()
        //                //.setExpectedAudience("ctd")
        //                .setSkipAllValidators()
        //                .setVerificationKey(key)
        //                .build();
        //
        //        context = jwtConsumer.process(jwt);
        //        System.out.println(context.getJwtClaims().getRawJson());
        //        jwtConsumer.processToClaims(jwt);

        validateSignature(algoType, jwt, subscriberId, subject, passwordHash);

        System.out.print("******************");

    }

    private void parseResponse(String jwt) throws InvalidJwtException {
        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setSkipSignatureVerification()
                .setSkipAllValidators()
                .build();

        JwtContext context = jwtConsumer.process(jwt);
        System.out.println(context.getJwtClaims().toJson());
    }

    private void validateSignature(AlgoType algoType, String jwt,
            String subscriberId, String user,
            String passwordHash) throws InvalidJwtException, UnsupportedEncodingException, DecoderException {
        Key key = deriveKey(algoType, subscriberId, user, passwordHash);
        System.out.println("key: " + new String(key.getEncoded()));

        JwtConsumer consumer = new JwtConsumerBuilder()
                //.setExpectedAudience("ctd")
                .setSkipAllValidators()
                .setVerificationKey(key)
                .build();

        JwtContext context = consumer.process(jwt);
        System.out.println(context.getJwtClaims().getRawJson());
        //consumer.processToClaims(jwt);
    }

    private Request getRequest(JwtClaims claims) throws IOException {
        Request request = null;
        Object requestObj = claims.getClaimValue("request");
        System.out.println("&&&&& " + claims.getClaimValue("request"));
        if (requestObj instanceof HashMap) {
            HashMap<String, Object> map = (HashMap) requestObj;
            request = new Request();
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

    private AlgoType getAlgoType(String alg) throws InvalidJwtException {

        AlgoType algoType;

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

    public Key generateKey(AlgoType algo, String subscriberId,
            String user,
            String password) throws UnsupportedEncodingException {
        //SHA256($subscriber_id + "/" + $sub + ":" + SHA256($subscriber_id + $password))
        //HMAC_SHA256
        String subIdPwd = String.format("%1$s%2$s", subscriberId, password);
        System.out.println("Hello1: " + subIdPwd);
        //subIdPwd = StringEscapeUtils.escapeHtml3(subIdPwd);
        subIdPwd = StringUtils.replace(subIdPwd, "*", "%2A");
        System.out.println("Hello2: " + subIdPwd);
        byte[] pwdHash = getShaHash2(algo, subIdPwd.getBytes("UTF-8"));
        System.out.println("Hello3: " + new String(pwdHash));
        String subIdUser = String.format("%1$s/%2$s:", subscriberId, user);
        byte[] subIdUserPwdHash =
                ArrayUtils.addAll(subIdUser.getBytes("UTF-8"), pwdHash);
        //System.out.println("Hello4: " + new String(subIdUserPwdHash));
        byte[] hash = getShaHash2(algo, subIdUserPwdHash);
        //System.out.println("Hello5: " + new String(hash));
        Key key = new HmacKey(hash);

        return key;
    }

    public Key deriveKey(AlgoType algo, String subscriberId,
            String user,
            String encodedpassword) throws UnsupportedEncodingException, DecoderException {


        byte[] pwdHash = Hex.decodeHex(encodedpassword.toCharArray());
        //encodedpassword.getBytes("UTF-8");
        String subIdUser = String.format("%1$s/%2$s:", subscriberId, user);
        byte[] subIdUserPwdHash =
                ArrayUtils.addAll(subIdUser.getBytes("UTF-8"), pwdHash);

        byte[] hash = getShaHash2(algo, subIdUserPwdHash);
        System.out.println("^^^Hello5: " + new String(hash));
        Key key = new HmacKey(hash);
        return key;
    }

    /*
    func (auth *Auth) deriveKey(sid uint64, acc string) ([]byte, error) {
	// Fetch the users.
	users, err := auth.Cli.fetchUsers()
	if err != nil {
		return nil, errorln(AuthError, err)
	}

	// Grab the SHA2 password.
	pwd := users[fmt.Sprintf("%v:%v:SHA2", sid, acc)]
	if pwd == "" {
		return nil, errorf(AuthError, "Cannot find SHA2 password for “%v/%v”", sid, acc)
	}

	// Convert it to bytes.
	pdata, err := hex.DecodeString(pwd)
	if err != nil {
		return nil, errorf(AuthError, "Cannot decode password: %v", err)
	}

	// Okay, turn it into a key.
	hash := sha256.Sum256(
		append([]byte(fmt.Sprintf("%v/%v:", sid, acc)), pdata...),
	)
	return hash[:], nil
}
     */


    public byte[] getShaHash2(AlgoType algo, byte[] data)
            throws UnsupportedEncodingException {
        byte[] hash;

        switch (algo) {
            case SHA384:
                hash = DigestUtils.sha384(data);
                break;
            case SHA512:
                hash = DigestUtils.sha512(data);
                break;
            default:
                hash = DigestUtils.sha256(data);
                System.out.println("&&&&&&& " + DigestUtils.sha256Hex(data));
        }

        return hash;
    }


    public void test1() throws IOException, MalformedClaimException, InvalidJwtException, DecoderException {
        String jwt2 =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJjdGQiLCJleHAiOjE0ODQ2MTQzNDYsImlhdCI6MTQ4NDYxNDA0NiwiaXNzIjoic2lkOjgwMDQyIiwianRpIjoiYzAyNGVkNTEtYjY1ZC00NjM3LTk2MTYtZjI3MGZhODFlN2UwIiwicmVxdWVzdCI6eyJtZXRoIjoiR0VUIiwicGF0aCI6Ii9mb28vYmFyIn0sInN1YiI6Ik9MVFAifQ.SBurh_fr-40vMYVZWYQC_6i9vwDnLEuhYcGN6xBBkHE";
        parseToken(jwt2, "abcd1234", "ctd");
    }

    private String getEncodedPassword(String subscriberId,
            String user,
            String password) throws UnsupportedEncodingException {

        //String subIdPwd = String.format("%1$s%2$s", subscriberId, password);
        //String subIdPwd = subscriberId + password;
        String subIdPwd = "0" + password;
        //String subIdPwd = password + subscriberId;
        //String subIdPwd = String.valueOf(204700) + "KWBKGSZH";
        String subIdPwdx = encodePassword(subIdPwd);
        System.out.println(
                "&&&&&&& 1 " + subIdPwdx + " - " + DigestUtils.sha256Hex(
                        subIdPwdx));
        //System.out.println(CryptoUtils.generateSha2PasswordForBetaAndLegacy(subscriberId + password));
        //        System.out.println("&&&&&&& 2: " + password + ": " + DigestUtils.sha256Hex(password.getBytes("UTF-8")));
        //        subIdPwd = String.format("%1$s%2$s:SHA2", subscriberId, password);
        //        System.out.println("&&&&&&& 3: " + subIdPwd + ": "  + DigestUtils.sha256Hex(subIdPwd.getBytes("UTF-8")));
        //        subIdPwd = String.format("%1$s:%2$s:%3$s", subscriberId, user, password);
        //        System.out.println("&&&&&&& 4: " + subIdPwd + ": "  + DigestUtils.sha256Hex(subIdPwd.getBytes("UTF-8")));
        //        subIdPwd = String.format("%1$s:%2$s:%3$s:SHA2", subscriberId, user, password);
        //        System.out.println("&&&&&&& 5: " + subIdPwd + ": "  + DigestUtils.sha256Hex(subIdPwd.getBytes("UTF-8")));

        return null;

    }

    public static String encodePassword(String password) {
        String encoded = urlEncode(password);
        encoded = StringUtils.replace(encoded, "*", "%2A");
        return encoded;
    }

    public static String urlEncode(String value) {
        return urlEncode(value, "UTF-8");
    }

    public static String urlEncode(String value, String encoding) {
        try {
            return value == null ? "" : (StringUtils.isBlank(
                    value) ? value : URLEncoder.encode(value, encoding));
        } catch (UnsupportedEncodingException var3) {
            return null;
        }
    }

    public void test2() throws IOException, JoseException, MalformedClaimException, InvalidJwtException, DecoderException {
        Request req = new Request();
        req.setMeth("POST");
        req.setPath(
                "/api/auth/custard/subscribers/898700/accounts/iouser/overrides");

        String jwt =
                generateRequestToken("sid:898700", "OLTP", "caa", "56J3B1RK",
                        AlgoType.SHA256, req);

        System.out.println(jwt);
        //        try {
        //            Thread.currentThread().sleep(60*1000);
        //        } catch (InterruptedException e) {
        //            e.printStackTrace();
        //        }

        parseToken(jwt,
                "049b60df9c299e8e4cb9898d1a67afb1555ea309041404839ad1bec4ba64faf7",
                "caa");

    }

    public void test3() throws MalformedClaimException, DecoderException, InvalidJwtException, IOException {
        String jwt =
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJjdGQiLCJzdWIiOiJPTFRQIiwiYXVkIjoic2lkOjg5ODcwMCIsImp0aSI6ImZTLVpDNDFTblZXcy1RS1dXRTVYTmciLCJleHAiOjE0ODUyMDU0MDcsIm5iZiI6MTQ4NTIwNDk4NywiaWF0IjoxNDg1MjA1MTA3LCJyZXNwb25zZSI6IntcInN0YXR1c1wiOjIwMSxcImZ1bmNcIjpcIlNIQTI1NlwiLFwiaGFzaFwiOlwiNDdERVFwajhIQlNhKy9USW1XKzVKQ2V1UWVSa201Tk1wSldaRzNoU3VGVT1cIn0ifQ.uDnAUaic8WLB7LjeHG1cuL0Tn-ErGC3ez7dzwkn6Rgo";
        //
        // parseRequestToken(jwt,
        //                "049b60df9c299e8e4cb9898d1a67afb1555ea309041404839ad1bec4ba64faf7");

        parseResponse(jwt);
    }


    public static void main(
            String[] args) throws JoseException, IOException, InvalidJwtException, MalformedClaimException, DecoderException {
        Jose4jExample4 ex = new Jose4jExample4();
        ex.test2();
        //ex.getEncodedPassword("204700", "OLTP", "N5CEDB29");
        //ex.test3();
    }
}
