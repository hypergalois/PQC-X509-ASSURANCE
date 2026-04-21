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
        name = "w_san_should_not_be_critical",
        description = "subjectAlternativeName SHOULD NOT be marked critical unless the subject field is an empty sequence.",
        citation = "7.1.2.3.h",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SanShouldNotBeCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        boolean isSubjectEmpty = Utils.isSubjectDNEmpty(certificate);

        if (!isSubjectEmpty && Utils.isExtensionCritical(certificate, Extension.subjectAlternativeName.getId())) {
            return LintResult.of(Status.WARN, "subject is not empty, but subjectAlternativeName is marked critical");
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) &&
                Utils.hasExtension(certificate, Extension.subjectAlternativeName.getId()) &&
                SMIMEUtils.isSMIMEBRCertificate(certificate);
    }

}
