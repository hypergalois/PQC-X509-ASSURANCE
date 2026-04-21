package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;


/**************************************************************************************************
 BRs: 7.1.2.3
 authorityInformationAccess
 With the exception of stapling, which is noted below, this extension MUST be present. It MUST NOT be
 marked critical, and it MUST contain the HTTP URL of the Issuing CA’s OCSP responder (accessMethod
 = 1.3.6.1.5.5.7.48.1). It SHOULD also contain the HTTP URL of the Issuing CA’s certificate
 (accessMethod = 1.3.6.1.5.5.7.48.2). See Section 13.2.1 for details.
 ***************************************************************************************************/

@Lint(
        name = "e_sub_cert_aia_missing",
        description = "Subscriber Certificate: authorityInformationAccess MUST be present.",
        citation = "BRs: 7.1.2.3",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class SubCertAiaMissing implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.hasAuthorityInformationAccessExtension(certificate)) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.isCA(certificate);
    }

}
