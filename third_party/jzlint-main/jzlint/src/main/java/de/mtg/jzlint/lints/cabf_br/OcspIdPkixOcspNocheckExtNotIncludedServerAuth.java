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
        name = "e_ocsp_id_pkix_ocsp_nocheck_ext_not_included_server_auth",
        description = "OCSP signing Certificate MUST contain an extension of type id-pkixocsp-nocheck, as defined by RFC6960",
        citation = "BRs: 4.9.9",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class OcspIdPkixOcspNocheckExtNotIncludedServerAuth implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.hasExtension(certificate, "1.3.6.1.5.5.7.48.1.5")) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isDelegatedOCSPResponderCert(certificate) && Utils.isServerAuthCert(certificate);
    }


}
