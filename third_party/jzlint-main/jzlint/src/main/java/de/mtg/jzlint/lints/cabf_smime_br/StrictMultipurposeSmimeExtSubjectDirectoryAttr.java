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
        name = "e_strict_multipurpose_smime_ext_subject_directory_attr",
        description = "SMIME Strict and Multipurpose certificates cannot have Subject Directory Attributes",
        citation = "BRs: 7.1.2.3j",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class StrictMultipurposeSmimeExtSubjectDirectoryAttr implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.hasExtension(certificate, Extension.subjectDirectoryAttributes.getId())) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) &&
                (SMIMEUtils.isStrictSMIMECertificate(certificate) ||
                        SMIMEUtils.isMultipurposeSMIMECertificate(certificate));
    }

}
