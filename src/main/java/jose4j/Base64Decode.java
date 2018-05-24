package jose4j;

import java.io.UnsupportedEncodingException;
import org.jose4j.base64url.Base64;

/**
 * {@code Base64Decode}
 *
 * @author Indra Basak
 * @since 1/11/17
 */
public class Base64Decode {

    public static void main(String[] args) throws UnsupportedEncodingException {
        String jwtToken =
                "eyJpc3MiOiJzaWQ6ODAwNDIiLCJzdWIiOiJPTFRQIiwiYXVkIjoiY3RkIiwiZXhwIjoxNDg0MDg2NzIzLCJuYmYiOjE0ODQwODYwMDMsImlhdCI6MTQ4NDA4NjEyMywianRpIjoiQ3Y4V1lGS092bWFmU1FYdzlSdFZTUSIsInJlcXVlc3QiOiJ7XCJtZXRob2RcIjpcIlBPU1RcIixcInBhdGhcIjpcIi9hdXRoL29yZy84MDA0Mi9ldmVudHMvXCIsXCJhbGdvcml0aG1cIjpcIlMyNTZcIixcImJvZHlcIjpcIjk5OTQxZjNjZDQzYzM2NDJmOGYyMTUxZDJjYTM5YzgyMzEwNTk1Y2EzNDNjMTgyNDk5YWM1MGMwYzhhZDAyMTVcIn0ifQ";

        byte[] bytes = jwtToken.getBytes("UTF-8");
        String jsonToken =
                new String(Base64.decode(jwtToken));

        System.out.println(jsonToken);
    }
}
