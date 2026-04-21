package de.mtg.jzlint.lints.cabf_smime_br;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_san_shall_be_present",
        description = "Subject alternative name SHALL be present",
        citation = "7.1.2.3.h",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SanShallBePresent implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.hasExtension(certificate, Extension.subjectAlternativeName.getId())) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR, "SMIME certificate does not have a subject alternative name extension");
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) && SMIMEUtils.isSMIMEBRCertificate(certificate);
    }

}
