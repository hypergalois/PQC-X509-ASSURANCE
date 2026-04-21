package de.mtg.jzlint.lints.community;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;


@Lint(
        name = "w_multiple_issuer_rdn",
        description = "Certificates should not have multiple attributes in a single RDN (issuer)",
        citation = "awslabs certlint",
        source = Source.COMMUNITY,
        effectiveDate = EffectiveDate.ZERO)
public class MultipleIssuerRdn implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            if (Utils.hasMultiValuedRDNInIssuer(certificate)) {
                return LintResult.of(Status.WARN);
            }
        } catch (CertificateEncodingException ex) {
            return LintResult.of(Status.FATAL);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }

}
