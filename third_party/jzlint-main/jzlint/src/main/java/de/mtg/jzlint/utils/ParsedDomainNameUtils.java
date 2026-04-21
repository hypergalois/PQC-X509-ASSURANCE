package de.mtg.jzlint.utils;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;


public final class ParsedDomainNameUtils {


    private static HashMap<X509Certificate, List<ParsedDomainName>> CACHE = new HashMap<>();

    private ParsedDomainNameUtils() {
        // empty
    }

    public static List<ParsedDomainName> getParsedDomains(X509Certificate certificate) throws IOException {

        if (CACHE.containsKey(certificate)) {
            return CACHE.get(certificate);
        }

        List<ParsedDomainName> parsedDomains = new ArrayList<>();

        List<AttributeTypeAndValue> commonName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.commonName.getId());

        for (AttributeTypeAndValue attributeTypeAndValue : commonName) {
            String value = attributeTypeAndValue.getValue().toString();
            if (!value.isEmpty() && !Utils.isIPAddress(value)) {
                parsedDomains.add(ParsedDomainName.fromDomain(value));
            }
        }
        List<String> dnsNames = Utils.getDNSNames(certificate);
        dnsNames.forEach(domain -> parsedDomains.add(ParsedDomainName.fromDomain(domain)));
        CACHE.put(certificate, parsedDomains);
        return parsedDomains;
    }

    public static boolean containsError(List<ParsedDomainName> parsedDomains) {
        return !parsedDomains.stream().map(ParsedDomainName::getError).allMatch(Objects::isNull);
    }

    public static List<String> getSLDs(List<ParsedDomainName> parsedDomains) {
        List<String> slds = new ArrayList<>();
        parsedDomains.stream().map(ParsedDomainName::getSld).forEach(slds::add);
        return slds;
    }

    public static List<String> getTRDs(List<ParsedDomainName> parsedDomains) {
        List<String> trds = new ArrayList<>();
        parsedDomains.stream().map(ParsedDomainName::getTrd).forEach(trds::add);
        return trds;
    }

    public static void cleanCacheEntry(X509Certificate certificate) {
        CACHE.remove(certificate);
    }

}

