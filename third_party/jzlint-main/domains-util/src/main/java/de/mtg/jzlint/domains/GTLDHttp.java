package de.mtg.jzlint.domains;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;

import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

public class GTLDHttp {

    /**
     * @param args first argument proxy (optional), second argument proxy port (optional).
     *
     * @throws IOException if writing on the filesystem is not possible.
     */
    public static void main(String[] args) throws IOException {

        List<GTLD> firstGTLDs;
        List<String> foundGTLDs = new ArrayList<>();

        {
            final String url = "https://www.icann.org/resources/registries/gtlds/v2/gtlds.json";
            RestTemplate restTemplate = getRestTemplate(args);
            UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(url);
            ResponseEntity<GTLDResponse> gtldResponse = restTemplate.getForEntity(builder.toUriString(), GTLDResponse.class);
            firstGTLDs = gtldResponse.getBody().getgTLDs();
        }

        firstGTLDs.stream().forEach(g -> foundGTLDs.add(g.getgTLD()));

        List<GTLD> secondGTLDs = new ArrayList<>();

        {
            final String uri = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt";
            RestTemplate restTemplate = getRestTemplate(args);
            UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(uri);
            ResponseEntity<String> response = restTemplate.getForEntity(builder.toUriString(), String.class);

            String data = response.getBody();

            String[] lines = data.split("\n");

            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                if (line.trim().startsWith("#")) {
                    continue;
                }

                String gtldName = line.trim().toLowerCase();

                if (foundGTLDs.contains(gtldName)) {
                    continue;
                }

                GTLD gtld = new GTLD();
                gtld.setgTLD(line.trim().toLowerCase());
                gtld.setDelegationDate("1985-01-01");
                secondGTLDs.add(gtld);
            }
        }

        TreeMap<String, GTLD> sortingMap = new TreeMap<>();

        firstGTLDs.stream().forEach(entry -> sortingMap.put(entry.getgTLD(), entry));
        secondGTLDs.stream().forEach(entry -> sortingMap.put(entry.getgTLD(), entry));

        GTLD onionGTLD = new GTLD();
        onionGTLD.setgTLD("onion");
        onionGTLD.setDelegationDate("2015-02-18");
        sortingMap.put(onionGTLD.getgTLD(), onionGTLD);

        String filename = "jzlint/src/main/resources/gtldMap.csv";

        System.out.printf("Writing CSV file to %s%n", filename);
        Files.write(Paths.get(filename), getEntriesAsCSVLines(sortingMap));

    }

    private static byte[] getEntriesAsCSVLines(TreeMap<String, GTLD> sortingMap) {

        Set<String> keys = sortingMap.keySet();

        StringBuilder stringBuilder = new StringBuilder();

        for (String key : keys) {
            stringBuilder.append(key);
            stringBuilder.append(",");
            stringBuilder.append(sortingMap.get(key).getDelegationDate());
            stringBuilder.append(",");
            stringBuilder.append(sortingMap.get(key).getgTLD());
            stringBuilder.append(",");
            String removalDate = sortingMap.get(key).getRemovalDate();
            if (removalDate != null) {
                stringBuilder.append(removalDate);
            }
            stringBuilder.append("\n");
        }

        return stringBuilder.toString().getBytes(Charset.forName("UTF-8"));
    }

    protected static RestTemplate getRestTemplate(String[] args) {

        if (args == null || args.length == 0 || args[0] == null || args[1] == null) {
            return new RestTemplate();
        }

        String proxyHost = args[0];
        int proxyPort = Integer.parseInt(args[1]);
        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, proxyPort));
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setProxy(proxy);
        return new RestTemplate(requestFactory);
    }

}
