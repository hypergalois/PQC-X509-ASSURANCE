package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_br_prohibit_dsa_usage",
        description = "DSA was removed from the Baseline Requirements as a valid signature algorithm in 1.7.1.",
        citation = "BRs: v1.7.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABFBRs_1_7_1_Date)
public class BrProhibitDsaUsage implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.isPublicKeyDSA(certificate)) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }


}
