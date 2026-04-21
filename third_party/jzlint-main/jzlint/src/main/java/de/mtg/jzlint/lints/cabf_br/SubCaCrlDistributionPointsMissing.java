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
 BRs: 7.1.2.2b cRLDistributionPoints
 This extension MUST be present and MUST NOT be marked critical.
 It MUST contain the HTTP URL of the CA’s CRL service.
 ************************************************/

@Lint(
        name = "e_sub_ca_crl_distribution_points_missing",
        description = "Subordinate CA Certificate: cRLDistributionPoints MUST be present and MUST NOT be marked critical.",
        citation = "BRs: 7.1.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class SubCaCrlDistributionPointsMissing implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.hasCRLDPExtension(certificate)) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubCA(certificate);
    }

}
