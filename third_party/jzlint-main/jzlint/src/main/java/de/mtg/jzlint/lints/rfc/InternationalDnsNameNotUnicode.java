package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.net.IDN;
import java.security.cert.X509Certificate;
import java.util.List;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;


@Lint(
        name = "e_international_dns_name_not_unicode",
        description = "Internationalized DNSNames punycode not valid Unicode",
        citation = "RFC 3490",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC3490)
public class InternationalDnsNameNotUnicode implements JavaLint {

    public static final String XN_PREFIX = "xn--";

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<String> dnsNames;
        try {
            dnsNames = Utils.getDNSNames(certificate);
        } catch (IOException ex) {
            return LintResult.of(Status.FATAL);
        }

        for (String dnsName : dnsNames) {

            String[] labels = dnsName.split("\\.");
            for (String label : labels) {
                if (label.toLowerCase().startsWith(XN_PREFIX)) {
                    String unicodeString = IDN.toUnicode(label);
                    if (unicodeString.toLowerCase().startsWith(XN_PREFIX)) {
                        return LintResult.of(Status.ERROR);
                    }
                }
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        try {
            return Utils.hasDNSNames(certificate);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
