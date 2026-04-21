package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 CA/Browser Forum BRs: 7.1.2.7.6 Subscriber Certificate Extensions

 | __Extension__                     | __Presence__    | __Critical__ | __Description__ |
 | ----                              | -               | -            | ----- |
 | `basicConstraints`                | MAY             | Y            | See [Section 7.1.2.7.8](#71278-subscriber-certificate-basic-constraints) |
 ************************************************/

@Lint(
        name = "e_sub_cert_basic_constraints_not_critical",
        description = "basicConstraints MAY appear in the certificate, and when it is included MUST be marked as critical",
        citation = "CA/Browser Forum BRs: 7.1.2.7.6",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SC62_EFFECTIVE_DATE)
public class SubCertBasicConstraintsNotCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (!Utils.isBasicConstraintsExtensionCritical(certificate)) {
            return LintResult.of(Status.ERROR, "Basic Constraints extension is present and marked as non-critical");
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasBasicConstraintsExtension(certificate) && Utils.isSubscriberCert(certificate);
    }

}
