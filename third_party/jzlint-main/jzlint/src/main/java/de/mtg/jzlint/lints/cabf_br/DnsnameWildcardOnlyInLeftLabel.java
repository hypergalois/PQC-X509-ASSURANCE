package de.mtg.jzlint.lints.cabf_br;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_dnsname_wildcard_only_in_left_label",
        description = "DNSName should not have wildcards except in the left-most label",
        citation = "BRs: 1.6.1, Wildcard Domain Name",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class DnsnameWildcardOnlyInLeftLabel implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            List<String> commonName = Utils.getAllAttributeValuesInSubject(certificate, X509ObjectIdentifiers.commonName.getId());
            List<String> dnsNames = Utils.getDNSNames(certificate);

            for (String commonNameValue : commonName) {
                if (!Utils.isIPAddress(commonNameValue) && !commonName.isEmpty()) {
                    dnsNames.add(commonNameValue);
                }
            }

            for (String dnsName : dnsNames) {
                String[] labels = dnsName.split("\\.");

                if (labels.length > 1) {
                    for (int i = 1; i < labels.length; i++) {
                        String label = labels[i];
                        if (label.startsWith("*")) {
                            return LintResult.of(Status.ERROR);
                        }
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
        return true;
    }

}
