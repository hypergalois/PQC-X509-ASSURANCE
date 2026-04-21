package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/******************************************************************************
 BRs: 7.1.2.3
 certificatePolicies
 This extension MUST be present and SHOULD NOT be marked critical.
 ******************************************************************************/
@Lint(
        name = "e_sub_cert_certificate_policies_missing",
        description = "Subscriber Certificate: certificatePolicies MUST be present and SHOULD NOT be marked critical.",
        citation = "BRs: 7.1.2.3",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class SubCertCertificatePoliciesMissing implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.hasCertificatePoliciesExtension(certificate)) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.isCA(certificate);
    }

}
