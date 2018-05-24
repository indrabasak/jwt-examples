package pb;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * {@code PbParser}
 *
 * @author Indra Basak
 * @since 1/28/17
 */
public class PbParser {

    Map<Integer, Integer> numbers = new HashMap<>();
    Map<Integer, Integer> power = new HashMap<>();
    Map<Integer, Integer> mult = new HashMap<>();


    public void tabulate(String fileName) throws IOException {
        numbers.clear();
        power.clear();
        mult.clear();

        try (Stream<String> stream = Files.lines(Paths.get(fileName))) {
            //stream.forEach(System.out::println);
            stream.forEach(e -> {
                String line = e.trim();
                //System.out.println(line);
                if (line.length() > 0) {
                    String[] tokens = line.split(":");
                    if (tokens.length == 2) {
                        //System.out.println(tokens[1]);
                        String[] nums = tokens[1].split("-");
                        if (nums.length == 6) {
                            for (int i = 0; i < 5; i++) {
                                //System.out.println(nums[i].trim());
                                int num = Integer.parseInt(nums[i].trim());
                                addNumber(numbers, num);
                            }
                            addNumber(power, Integer.parseInt(nums[5].trim()));
                        }
                    }
                }
            });
        }
        print();
    }

    public void tabulateTabbedFile(String fileName) throws IOException {
        numbers.clear();
        power.clear();
        mult.clear();

        Stream<String> stream = Files.lines(Paths.get(fileName));
        stream.forEach(e -> {
            String line = e.trim();
            //System.out.println(line);
            if (line.length() > 0) {
                String[] tokens = line.split("\t");
                if (tokens.length == 9) {
                    for (int i = 2; i < 7; i++) {
                        addNumber(numbers, Integer.parseInt(tokens[i].trim()));
                    }
                }
                addNumber(power, Integer.parseInt(tokens[7].trim()));
                addNumber(mult, Integer.parseInt(tokens[8].trim()));
            }
        });
        print();
    }

    private void addNumber(Map<Integer, Integer> bucket, int num) {
        if (bucket.containsKey(num)) {
            int count = bucket.get(num);
            bucket.put(num, count + 1);
        } else {
            bucket.put(num, 1);
        }
    }

    private void print() {
        System.out.println("--- Numbers ---");
        print(numbers);

        System.out.println("--- Power ---");
        print(power);

        System.out.println("--- Multiplier ---");
        print(mult);
    }

    private void print(Map<Integer, Integer> map) {
        Map<Integer, Integer> sortedMap =
                map.entrySet().stream().sorted(
                        Map.Entry.<Integer, Integer>comparingByValue().reversed()).collect(
                        Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue,
                                (e1, e2) -> e1, LinkedHashMap::new));
        sortedMap.entrySet().forEach(e -> {
            System.out.println(e.getKey() + " - " + e.getValue());
        });
    }

    public static void main(String[] args) throws IOException {
        PbParser parser = new PbParser();
        //parser.tabulate("/Users/indra.basak/Documents/pb.txt");
        parser.tabulateTabbedFile("/Users/indra.basak/Documents/pb-tab.txt");
    }
}
