package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/*******************************************************************************************************
 BRs: 7.1.2.3
 extKeyUsage (required)
 Either the value id-kp-serverAuth [RFC5280] or id-kp-clientAuth [RFC5280] or
 both values MUST be present. id-kp-emailProtection [RFC5280] MAY be present.
 Other values SHOULD NOT be present. The value anyExtendedKeyUsage MUST NOT be
 present.
 *******************************************************************************************************/

@Lint(
        name = "e_sub_cert_eku_missing",
        description = "Subscriber certificates MUST have the extended key usage extension present",
        citation = "BRs: 7.1.2.3",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class SubCertEkuMissing implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.hasExtendedKeyUsageExtension(certificate)) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.isCA(certificate);
    }

}
