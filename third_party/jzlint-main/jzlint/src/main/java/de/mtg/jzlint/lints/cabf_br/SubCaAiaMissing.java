package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.IneffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/***********************************************
 CAB 7.1.2.2c
 With the exception of stapling, which is noted below, this extension MUST be present. It MUST NOT be
 marked critical, and it MUST contain the HTTP URL of the Issuing CA’s OCSP responder (accessMethod
 = 1.3.6.1.5.5.7.48.1). It SHOULD also contain the HTTP URL of the Issuing CA’s certificate
 (accessMethod = 1.3.6.1.5.5.7.48.2).
 ************************************************/

@Lint(
        name = "e_sub_ca_aia_missing",
        description = "Subordinate CA Certificate: authorityInformationAccess MUST be present, with the exception of stapling.",
        citation = "BRs: 7.1.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate,
        ineffectiveDate = IneffectiveDate.CABFBRs_1_7_1_Date)
public class SubCaAiaMissing implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (!Utils.hasExtension(certificate, Extension.authorityInfoAccess.getId())) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubCA(certificate);
    }

}
