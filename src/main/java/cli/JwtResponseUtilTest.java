package cli;

/**
 * {@code JwtResponseUtil}
 *
 * @author Indra Basak
 * @since 1/27/17
 */
public class JwtResponseUtilTest {

    public static void testParseResponseToken() throws JwtException {
        String jwt =
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJjYWEiLCJzdWIiOiJPTFRQIiwiYXVkIjoic2lkOjg5ODcwMCIsImp0aSI6IlNGTjNmbDBjamsxb3JxVEFaZlRiU3ciLCJleHAiOjE0ODU3NDI4NzcsIm5iZiI6MTQ4NTc0MjQ1NywiaWF0IjoxNDg1NzQyNTc3LCJyZXNwb25zZSI6IntcInN0YXR1c1wiOjIwMSxcImZ1bmNcIjpcIlNIQTI1NlwiLFwiaGFzaFwiOlwiU3J5TEdrakpwT0J5a0hUQWkyaVZwcElieXNUUEYzbGpabFRMQkNZYlRaTT1cIn0ifQ.GWedhZTtKPFskX29pIvzyTVL9YDHW9g4jJ8Io6bWeqE";

        Response rsp = new Response();
        rsp.setStatus(201);
        rsp.setBody(
                "{\"overrideId\":\"c9b131a4-ff97-4b8d-ae72-7f91922a7a15\",\"subscriberId\":\"898700\",\"type\":\"ACCOUNT\",\"strength\":\"HARD\",\"ttlSeconds\":7000,\"txnId\":\"f1d9185a-d729-3340-b67f-32e4c8317154\",\"txnDate\":\"2017-01-30T02:16:16.724+0000\",\"user\":\"indra\",\"accountCode\":\"iouser\",\"_links\":[{\"rel\":\"self\",\"href\":\"http://localhost:8080/api/auth/custard/subscribers/898700/accounts/iouser/overrides/c9b131a4-ff97-4b8d-ae72-7f91922a7a15\"}]}");
        JwtResponseUtil.parseResponseToken(jwt, "56J3B1RK", rsp);
    }

    public static void main(String[] args) throws JwtException {
        testParseResponseToken();
    }
}
