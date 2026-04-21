package de.mtg.jzlint.lints.cabf_br;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_dnsname_contains_prohibited_reserved_label",
        description = "FQDNs MUST consist solely of Domain Labels that are P-Labels or Non-Reserved LDH Labels",
        citation = "BRs: 7.1.4.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.NoReservedDomainLabelsDate)
public class DnsnameContainsProhibitedReservedLabel implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        final String XN_PREFIX = "xn--";

        try {
            List<String> commonName = Utils.getAllAttributeValuesInSubject(certificate, X509ObjectIdentifiers.commonName.getId());
            List<String> dnsNames = Utils.getDNSNames(certificate);
            dnsNames.addAll(commonName);
            for (String dnsName : dnsNames) {
                String[] labels = dnsName.split("\\.");
                for (String label : labels) {
                    Pattern pattern = Pattern.compile("^..--.*");
                    Matcher matcher = pattern.matcher(label);
                    if (matcher.matches() && !label.toLowerCase().startsWith(XN_PREFIX)) {
                        return LintResult.of(Status.ERROR);
                    }
                }
            }

        } catch (CertificateEncodingException | IOException ex) {
            return LintResult.of(Status.FATAL);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        try {
            return Utils.isSubscriberCert(certificate) && Utils.dnsNamesExist(certificate);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
