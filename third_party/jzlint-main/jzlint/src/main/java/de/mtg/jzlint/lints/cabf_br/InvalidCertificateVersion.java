package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

/************************************************
 Certificates MUST be of type X.509 v3.
 ************************************************/

@Lint(
        name = "e_invalid_certificate_version",
        description = "Certificates MUST be of type X.590 v3",
        citation = "BRs: 7.1.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABV130Date)
public class InvalidCertificateVersion implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (certificate.getVersion() != 3) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }

}
