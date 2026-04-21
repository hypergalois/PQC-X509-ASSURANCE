package de.mtg.jzlint.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.StringTokenizer;

public final class GTLDUtils {

    public static final String DELEGATION_DATE = "delegationDate";
    public static final String G_TLD = "gTLD";
    public static final String REMOVAL_DATE = "removalDate";


    private GTLDUtils() {
        // empty
    }

    public static Map<String, Map<String, String>> getGTLDs() {

        // key is GTLD, value is a map with two keys gtld and delegationDate and corresponding values
        Map<String, Map<String, String>> gTLDs = new HashMap<>();

        ClassLoader classLoader = GTLDUtils.class.getClassLoader();

        byte[] buffer = new byte[1024];
        byte[] file;
        int length;
        try (InputStream inputStream = classLoader.getResourceAsStream("gtldMap.csv");
                ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            while ((length = inputStream.read(buffer)) != -1) {
                baos.write(buffer, 0, length);
            }

            file = baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        try (Scanner scanner = new Scanner(new String(file))) {
            while (scanner.hasNextLine()) {
                String entry = scanner.nextLine();
                StringTokenizer tokenizer = new StringTokenizer(entry, ",");
                String key = tokenizer.nextToken();
                String delegationDate = tokenizer.nextToken();
                String gTLD = tokenizer.nextToken();
                String removalDate = "";
                if (tokenizer.hasMoreTokens()) {
                    removalDate = tokenizer.nextToken();
                }
                Map<String, String> value = new HashMap<>();
                value.put(DELEGATION_DATE, delegationDate);
                value.put(G_TLD, gTLD);
                value.put(REMOVAL_DATE, removalDate);
                gTLDs.put(key, value);
            }
        }

        return gTLDs;
    }

    public static boolean gtldExists(String domain) {

        String gtld = getTLD(domain);
        Map<String, String> knownGTLD = getEntry(gtld);

        if (knownGTLD == null) {
            return false;
        }

        return knownGTLD.get(G_TLD).equalsIgnoreCase(gtld);
    }

    public static boolean gtldDidnotExist(String domain, ZonedDateTime certificateNotBefore) throws ParseException {
        return !gtldExisted(domain, certificateNotBefore);
    }

    public static boolean gtldExisted(String domain, ZonedDateTime certificateNotBefore) throws ParseException {

        String gtld = getTLD(domain);
        Map<String, String> knownGTLD = getEntry(gtld);

        if (knownGTLD == null) {
            return false;
        }

        if (!knownGTLD.get(G_TLD).equalsIgnoreCase(gtld)) {
            return false;
        }

        String delegationDate = knownGTLD.get(DELEGATION_DATE);
        String removalDate = knownGTLD.get(REMOVAL_DATE);

        ZonedDateTime zonedDelegationDate = getZonedDateTime(delegationDate);
        ZonedDateTime zonedRemovalDateDate = getZonedDateTime(removalDate);
        boolean certificateAfterOrOnDelegationDate = !certificateNotBefore.isBefore(zonedDelegationDate);
        boolean certificateBeforeRemovalDate = zonedRemovalDateDate == null || certificateNotBefore.isBefore(zonedRemovalDateDate);

        return certificateAfterOrOnDelegationDate && certificateBeforeRemovalDate;
    }

    private static ZonedDateTime getZonedDateTime(String date) throws ParseException {
        if (date == null || date.isEmpty()) {
            return null;
        }
        String pattern = "yyyy-MM-dd";
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
        Date delegationDateDate = simpleDateFormat.parse(date);
        return ZonedDateTime.ofInstant(delegationDateDate.toInstant(), ZoneId.of(DateUtils.UTC));
    }

    private static Map<String, String> getEntry(String key) {
        Map<String, Map<String, String>> gtlDs = getGTLDs();
        return gtlDs.get(key);
    }

    private static String getTLD(String domain) {
        if (domain == null || domain.lastIndexOf(".") == -1) {
            return null;
        }
        return domain.substring(domain.lastIndexOf(".") + 1);
    }

}
