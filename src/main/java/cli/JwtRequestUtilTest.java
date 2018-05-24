package cli;

import static cli.JwtRequestUtil.generateRequestToken;
import static cli.JwtRequestUtil.parseRequestToken;

/**
 * {@code JwtRequestUtilTest}
 *
 * @author Indra Basak
 * @since 1/24/17
 */
public class JwtRequestUtilTest {

    public static void testGenerateAndParseToken() throws JwtException {
        JwtRequest req = new JwtRequest();
        req.setMeth("POST");
        req.setPath(
                "/api/auth/custard/subscribers/898700/accounts/iouser/overrides");
        req.setBody("{\n" +
                "  \"strength\": \"harD\",\n" +
                "  \"ttlSeconds\": 7000,\n" +
                "  \"user\": \"indra\"\n" +
                "}");

        String jwt =
                generateRequestToken("sid:898700", "OLTP", "caa", "56J3B1RK",
                        AlgorithmType.SHA256, req);

        System.out.println(jwt);

        parseRequestToken(jwt,
                "049b60df9c299e8e4cb9898d1a67afb1555ea309041404839ad1bec4ba64faf7",
                "caa");
    }

    public static void main(String[] args) throws JwtException {
        testGenerateAndParseToken();
    }
}
