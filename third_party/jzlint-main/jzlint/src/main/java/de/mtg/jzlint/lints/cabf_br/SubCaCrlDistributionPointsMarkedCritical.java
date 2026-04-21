package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.Extension;

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
        name = "e_sub_ca_crl_distribution_points_marked_critical",
        description = "Subordinate CA Certificate: cRLDistributionPoints MUST be present and MUST NOT be marked critical.",
        citation = "BRs: 7.1.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class SubCaCrlDistributionPointsMarkedCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.isExtensionCritical(certificate, Extension.cRLDistributionPoints.getId())) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubCA(certificate) && Utils.hasCRLDPExtension(certificate);
    }

}
