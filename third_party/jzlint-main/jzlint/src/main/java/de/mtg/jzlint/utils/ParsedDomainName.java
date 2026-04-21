package de.mtg.jzlint.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public final class ParsedDomainName {

    public static final String ERROR_INVALID_DOMAIN = "Invalid TLD.";

    private final String tld;
    private final String sld;
    private final String trd;
    private final String error;

    private ParsedDomainName(String tld, String sld, String trd, String error) {
        this.tld = tld;
        this.sld = sld;
        this.trd = trd;
        this.error = error;
    }

    private static ParsedDomainName fromError(String error) {
        return new ParsedDomainName("", "", "", error);
    }

    private static List<Map<String, Boolean>> getMatchingRules(String domain, boolean publicOnly) {

        ClassLoader classLoader = ParsedDomainName.class.getClassLoader();

        byte[] buffer = new byte[1024];
        byte[] file;
        int length;
        try (InputStream inputStream = classLoader.getResourceAsStream("public_suffix_list.dat");
                ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            while ((length = inputStream.read(buffer)) != -1) {
                baos.write(buffer, 0, length);
            }

            file = baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String publicSuffixList = new String(file, StandardCharsets.UTF_8);

        List<Map<String, Boolean>> matchingRules = new ArrayList<>();
        boolean isPublicRule = true;

        String[] lines = publicSuffixList.split("\n");

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];

            if (line.contains("===BEGIN PRIVATE DOMAINS===") && publicOnly) {
                break;
            }

            if (line.contains("===BEGIN PRIVATE DOMAINS===")) {
                isPublicRule = false;
            }

            if (line.trim().startsWith("//")) {
                continue;
            }

            if (line.trim().isEmpty()) {
                continue;
            }

            String rule = line.trim();

            if (line.trim().startsWith("!")) {
                rule = line.trim().substring(1);
            }

            rule = IDN.toASCII(rule);

            if (DomainStringUtils.domainMatches(domain, rule)) {
                matchingRules.add(Collections.singletonMap(line.trim(), isPublicRule));
            }
        }

        return matchingRules;
    }

    /**
     * Algorithm:
     * <p>
     * 1. Match domain against all rules and take note of the matching ones.
     * 2. If no rules match, the prevailing rule is "*".
     * 3. If more than one rule matches, the prevailing rule is the one which is an exception rule.
     * 4. If there is no matching exception rule, the prevailing rule is the one with the most labels.
     * 5. If the prevailing rule is a exception rule, modify it by removing the leftmost label.
     * 6. The public suffix is the set of labels from the domain which match the labels of the prevailing rule, using the matching algorithm above.
     * 7. The registered or registrable domain is the public suffix plus one additional label.
     *
     * @param domain
     *
     * @return
     */
    private static Map<String, Boolean> getPrevailingRule(String domain, boolean publicOnly) {
        List<Map<String, Boolean>> matchingRules = getMatchingRules(domain, publicOnly);

        if (matchingRules.size() == 0) {
            return Collections.singletonMap("*", true);
        }

        for (Map<String, Boolean> matchingRule : matchingRules) {
            Optional<String> exclamationRule = matchingRule.keySet().stream().filter(rule -> rule.startsWith("!")).findFirst();
            if (exclamationRule.isPresent()) {
                String matchingRuleWithoutLeftmostLabel = StringUtils.getAfterFirstDot(exclamationRule.get()).get();
                return Collections.singletonMap(matchingRuleWithoutLeftmostLabel, matchingRule.entrySet().iterator().next().getValue());
            }
        }

        Map<String, Boolean> prevailingRule = null;

        int size = 0;
        for (Map<String, Boolean> matchingRule : matchingRules) {

            String rule = matchingRule.keySet().iterator().next();

            int matchingRuleLabelSize = DomainStringUtils.getLabels(rule).size();

            if (matchingRuleLabelSize > size) {
                size = matchingRuleLabelSize;
                prevailingRule = matchingRule;
            }
        }
        return prevailingRule;
    }

    private static String getPublicSuffix(String domain, Map<String, Boolean> prevailingRule) {

        String rule = prevailingRule.keySet().iterator().next();

        List<String> domainLabels = DomainStringUtils.getLabels(domain);
        List<String> ruleLabels = DomainStringUtils.getLabels(rule);
        StringBuilder publicSuffixBuilder = new StringBuilder();

        for (int i = 0; i < ruleLabels.size(); i++) {
            String ruleLabel = ruleLabels.get(i);
            String domainLabel = domainLabels.get(i);

            publicSuffixBuilder.insert(0, ".");
            publicSuffixBuilder.insert(1, domainLabel);

            if (ruleLabel.equals("*")) {
                return publicSuffixBuilder.deleteCharAt(0).toString();
            }

        }

        return publicSuffixBuilder.deleteCharAt(0).toString();
    }


    /**
     * Algorithm:
     * <p>
     * 1. Match domain against all rules and take note of the matching ones.
     * 2. If no rules match, the prevailing rule is "*".
     * 3. If more than one rule matches, the prevailing rule is the one which is an exception rule.
     * 4. If there is no matching exception rule, the prevailing rule is the one with the most labels.
     * 5. If the prevailing rule is a exception rule, modify it by removing the leftmost label.
     * 6. The public suffix is the set of labels from the domain which match the labels of the prevailing rule, using the matching algorithm above.
     * 7. The registered or registrable domain is the public suffix plus one additional label.
     *
     * @param domain
     *
     * @return
     */
    private static ParsedDomainName fromDomain(String domain, boolean publicOnly) {

        String canonicalizedDomain = IDN.toASCII(domain);

        Map<String, Boolean> prevailingRule = getPrevailingRule(canonicalizedDomain, publicOnly);

        String publicSuffix = getPublicSuffix(canonicalizedDomain, prevailingRule);

        Boolean isPublic = prevailingRule.entrySet().iterator().next().getValue();

        if (isPublic) {

            if (publicSuffix.equalsIgnoreCase(canonicalizedDomain)) {
                return new ParsedDomainName("", "", "", ERROR_INVALID_DOMAIN);
            }

            Optional<String> withoutEnding = StringUtils.getWithoutEnding(canonicalizedDomain, "." + publicSuffix);

            String notTLD = withoutEnding.get();
            String[] sldTrd = separateSLDAndTRD(notTLD);
            return new ParsedDomainName(IDN.toUnicode(publicSuffix), IDN.toUnicode(sldTrd[0]), IDN.toUnicode(sldTrd[1]), null);
        } else {
            return fromDomain(canonicalizedDomain, true);
        }
    }

    public static ParsedDomainName fromDomain(String domain) {
        return fromDomain(domain, false);
    }


    private static String[] separateSLDAndTRD(String input) {
        String[] returnValue = new String[2];
        String sld;
        String trd;
        if (input.contains(".")) {
            sld = StringUtils.getAfterLastDot(input).get();
            trd = StringUtils.getBeforeLastDot(input).get();
        } else {
            sld = input;
            trd = "";
        }

        returnValue[0] = sld;
        returnValue[1] = trd;
        return returnValue;
    }

    public String getTld() {
        return tld;
    }

    public String getSld() {
        return sld;
    }

    public String getTrd() {
        return trd;
    }

    public String getError() {
        return error;
    }
}
