package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/***********************************************
 CAB BR 1.7.1 Section 7.1.2.2c - authorityInformationAccess
 This extension SHOULD be present. It MUST NOT be marked critical.
 It SHOULD contain the HTTP URL of the Issuing CA’s certificate (accessMethod =
 1.3.6.1.5.5.7.48.2). It MAY contain the HTTP URL of the Issuing CA’s OCSP responder
 (accessMethod = 1.3.6.1.5.5.7.48.1).
 ************************************************/

@Lint(
        name = "w_sub_ca_aia_missing",
        description = "Subordinate CA Certificate: authorityInformationAccess SHOULD be present.",
        citation = "BRs: 7.1.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABFBRs_1_7_1_Date)
public class SubCaAiaMissingWarning implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.hasAuthorityInformationAccessExtension(certificate)) {
            return LintResult.of(Status.PASS);
        }

        return LintResult.of(Status.WARN);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isCA(certificate) && !Utils.isRootCA(certificate);
    }

}
