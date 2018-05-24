package cli;

import java.io.FileInputStream;
import java.io.IOException;
import org.apache.commons.io.IOUtils;

/**
 * {@code TestFile}
 *
 * @author Indra Basak
 * @since 1/30/17
 */
public class TestFile {

    public static void main(String[] args) {
        FileInputStream inputStream = null;
        try {
            inputStream = new FileInputStream(
                    "/Users/indra.basak/Documents/jwt-input.txt");
            String argLine = IOUtils.toString(inputStream, "UTF-8");
            System.out.println(argLine);
            String[] argx = argLine.split(" ");
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
    }
}
