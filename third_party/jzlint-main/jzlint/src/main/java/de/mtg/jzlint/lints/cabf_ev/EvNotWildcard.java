package de.mtg.jzlint.lints.cabf_ev;

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
import de.mtg.jzlint.utils.EVUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_ev_not_wildcard",
        description = "Wildcard certificates are not allowed for EV Certificates except for those with .onion as the TLD.",
        citation = "CABF EV Guidelines 1.7.8 Section 9.8.1",
        source = Source.CABF_EV_GUIDELINES,
        effectiveDate = EffectiveDate.OnionOnlyEVDate)
public class EvNotWildcard implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            List<String> commonNames = Utils.getAllAttributeValuesInSubject(certificate, X509ObjectIdentifiers.commonName.getId());
            List<String> dnsNames = Utils.getDNSNames(certificate);
            commonNames.addAll(dnsNames);

            for (String value : commonNames) {
                if (value.contains("*") && !value.endsWith(".onion")) {
                    return LintResult.of(Status.ERROR, String.format("%s appears to be a wildcard domain", value));
                }
            }
        } catch (CertificateEncodingException | IOException ex) {
            return LintResult.of(Status.FATAL);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return EVUtils.isEV(certificate);
    }

}
