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


/**********************************************************************
 RFC5280 suggested the addition of SKI extension, but CABF BR SC62
 marked the extension as NOT RECOMMENDED for subscriber certificates

 Warning:
 Users of zlint will trigger either
 `w_ext_subject_key_identifier_not_recommended_subscriber` (this lint)
 or `w_ext_subject_key_identifier_missing_sub_cert` the one enforcing
 RFC5280's behavior.

 Users are expected to specifically ignore one or the other lint
 depending on which one apply to them.

 See:
 - https://github.com/zmap/zlint/issues/749
 - https://github.com/zmap/zlint/issues/762
 **********************************************************************/

@Lint(
        name = "w_ext_subject_key_identifier_not_recommended_subscriber",
        description = "Subscriber certificates use of Subject Key Identifier is NOT RECOMMENDED",
        citation = "BRs v2: 7.1.2.7.6",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SC62_EFFECTIVE_DATE)
public class ExtSubjectKeyIdentifierNotRecommendedSubscriber implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.hasExtension(certificate, Extension.subjectKeyIdentifier.getId())) {
            return LintResult.of(Status.WARN);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate);
    }

}
