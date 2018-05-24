package cli;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 * {@code JwtCommandLine}
 *
 * @author Indra Basak
 * @since 1/30/17
 */
public class JwtCommandLine {

    private Options options = new Options();

    public JwtCommandLine() {
        //        options.addOption("a", "all", false,
        //                "do not hide entries starting with .");
        //        options.addOption("A", "almost-all", false,
        //                "do not list implied . and ..");
        //        options.addOption("b", "escape", false,
        //                "print octal escapes for nongraphic "
        //                        + "characters");
        //        options.addOption("h", "help", false, "show help.");

        OptionGroup group1 = new OptionGroup();
        group1.addOption(new Option("a", "all", false,
                "do not hide entries starting with ."));
        group1.addOption(new Option("b", "almost-all", false,
                "do not list implied . and .."));
        group1.addOption(new Option("c", "escape", false,
                "print octal escapes for nongraphic "
                        + "characters"));
        group1.addOption(new Option("h", "help", false, "show help."));
        options.addOptionGroup(group1);

        OptionGroup group2 = new OptionGroup();
        group2.addOption(new Option("x", "all", false,
                "do not hide entries starting with ."));
        group2.addOption(new Option("y", "almost-all", false,
                "do not list implied . and .."));
        group2.addOption(new Option("z", "escape", false,
                "print octal escapes for nongraphic "
                        + "characters"));
        group2.addOption(new Option("h", "help", false, "show help."));
        options.addOptionGroup(group2);
    }


    private void help() {
        // This prints out some help
        HelpFormatter formater = new HelpFormatter();
        formater.printHelp("Mainx", options);
        System.exit(0);
    }

    public void parse(String[] args) {
        // create the command line parser
        CommandLineParser parser = new DefaultParser();

        try {
            // parse the command line arguments
            CommandLine line = parser.parse(options, args);

            if (line.hasOption("h")) {
                help();
            }
        } catch (ParseException exp) {
            System.out.println("Unexpected exception:" + exp.getMessage());
        }
    }

    public static void main(String[] args) {
        JwtCommandLine cl = new JwtCommandLine();
        cl.parse(args);
    }
}
