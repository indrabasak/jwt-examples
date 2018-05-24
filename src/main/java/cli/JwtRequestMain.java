package cli;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.io.IOUtils;

import static cli.JwtRequestUtil.generateRequestToken;

/**
 * {@code JwtRequestMain}
 *
 * @author Indra Basak
 * @since 1/30/17
 */
public class JwtRequestMain {

    private static final String OPTION_ISS = "iss";
    private static final String OPTION_SUB = "sub";
    private static final String OPTION_AUD = "aud";
    private static final String OPTION_PWD = "p";
    private static final String OPTION_METH = "meth";
    private static final String OPTION_URL = "url";
    private static final String OPTION_BODY = "body";
    private static final String OPTION_FILE = "f";
    private Options options;

    public JwtRequestMain() {
        //generateRequestToken(String issuer, String subject,
        //        String audience, String password, AlgorithmType algoType,
        //                JwtRequest req)
        //iojmake --iss <issuer> -u <user> -p <password> --aud <audience> <url>
        options = new Options();

        options.addOption(new Option(OPTION_ISS, true,
                "The issuer of the JWT (required). Usually subscriber id"));
        options.addOption(new Option(OPTION_SUB, true,
                "The subject of the JWT (required). This identifies the party on behalf of whom the issuer is making the request. Usually subscriber account username"));
        options.addOption(new Option(OPTION_AUD, true,
                "The audience for the JWT (required). Should be the name of the service to which the request is sent. E.g., caa for Custard API"));
        options.addOption(new Option(OPTION_PWD, true,
                "API text password (required)"));
        options.addOption(new Option(OPTION_METH, true,
                "HTTP method of the request (required)"));
        options.addOption(new Option(OPTION_URL, true,
                "URL of the request (required)"));
        options.addOption(new Option(OPTION_BODY, true,
                "HTTP request body if any (optional)"));
        options.addOption(new Option("h", "help", false, "show help."));
    }

    public void run(String[] args) throws JwtException {
        CommandLineParser parser = new DefaultParser();

        try {
            // parse the command line arguments
            CommandLine line = parser.parse(options, args);

            if (line.hasOption("h")) {
                help();
            }

            readOptions(line);

        } catch (ParseException exp) {
            System.out.println("Unexpected exception:" + exp.getMessage());
            System.exit(0);
        }

    }

    private void help() {
        // This prints out some help
        HelpFormatter formater = new HelpFormatter();
        formater.printHelp("JwtRequestMain", options);
        System.exit(0);
    }

    private void readOptions(CommandLine line) {
        if (!line.hasOption(OPTION_ISS)) {
            System.out.println("Missing issuer");
            help();
        }

        if (!line.hasOption(OPTION_SUB)) {
            System.out.println("Missing subject");
            help();
        }

        if (!line.hasOption(OPTION_AUD)) {
            System.out.println("Missing audience");
            help();
        }

        if (!line.hasOption(OPTION_PWD)) {
            System.out.println("Missing password");
            help();
        }

        if (!line.hasOption(OPTION_METH)) {
            System.out.println("Missing HTTP method");
            help();
        }

        if (!line.hasOption(OPTION_URL)) {
            System.out.println("Missing HTTP URL");
            help();
        }

        String issuer = line.getOptionValue(OPTION_ISS);
        String subject = line.getOptionValue(OPTION_SUB);
        String audience = line.getOptionValue(OPTION_AUD);
        String password = line.getOptionValue(OPTION_PWD);
        String meth = line.getOptionValue(OPTION_METH);
        String url = line.getOptionValue(OPTION_URL);

        String body = null;
        if (line.hasOption(OPTION_BODY)) {
            body = line.getOptionValue(OPTION_BODY).trim();
            System.out.println(body);
            if (body != null && body.startsWith("@")) {
                body = readDataFromFile(body.substring(1));
            }
        }
        System.out.println(body);


        JwtRequest request = processRequest(meth, url, body);
        String jwt =
                null;
        try {
            jwt = generateRequestToken("sid:" + issuer, subject, audience,
                    password,
                    AlgorithmType.SHA256, request);
        } catch (JwtException e) {
            System.out.println(
                    "Failed to generate request JWT " + e.getMessage());
            System.exit(0);
        }
        System.out.println(jwt);
    }

    private String readDataFromFile(String fileName) {
        FileInputStream inputStream = null;
        String data = null;
        try {
            inputStream = new FileInputStream(fileName);
            data = IOUtils.toString(inputStream, "UTF-8").trim();
            System.out.println(data);
        } catch (Exception e) {
            System.out.println("Unexpected exception:" + e.getMessage());
            System.exit(0);
        } finally {
            try {
                inputStream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return data;
    }

    private JwtRequest processRequest(String meth, String url, String body) {
        JwtRequest request = new JwtRequest();

        request.setMeth(RequestMethod.valueOf(meth.toUpperCase()).toString());

        try {
            URL aUrl = new URL(url);
            System.out.println("path: " + aUrl.getPath());
            System.out.println("query: " + aUrl.getQuery());
            request.setPath(aUrl.getPath());
            request.setQuery(aUrl.getQuery());
        } catch (MalformedURLException e) {
            System.out.println("Invalid URL");
        }

        if (body != null) {
            System.out.println("body: " + body);
            request.setBody(body);
        }

        return request;
    }

    public static void main(String[] args) throws JwtException {
        new JwtRequestMain().run(args);
    }
}
