package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
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
        name = "e_rfc_dnsname_label_too_long",
        description = "DNSName labels MUST be less than or equal to 63 characters",
        citation = "RFC 5280: 4.2.1.6, citing RFC 1035",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class RfcDnsnameLabelTooLong implements JavaLint {

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
                if (label.length() >= 64) {
                    return LintResult.of(Status.ERROR);
                }
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        try {
            return Utils.isSubscriberCert(certificate) && Utils.hasDNSNames(certificate);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
