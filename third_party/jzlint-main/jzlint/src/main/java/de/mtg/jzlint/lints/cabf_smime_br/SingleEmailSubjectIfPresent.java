package de.mtg.jzlint.lints.cabf_smime_br;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.style.BCStyle;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_single_email_subject_if_present",
        description = "If present, the subject:emailAddress SHALL contain a single Mailbox Address",
        citation = "7.1.4.2.2.h",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SingleEmailSubjectIfPresent implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> dnEmails = Utils.getSubjectDNNameComponent(certificate, BCStyle.EmailAddress.getId());

        for (AttributeTypeAndValue attributeTypeAndValue : dnEmails) {
            String email = attributeTypeAndValue.getValue().toString();
            if (!SMIMEUtils.isValidEmailAddress(email)) {
                return LintResult.of(Status.ERROR, String.format("subject:emailAddress was present and contained an invalid email address (%s)", email));
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) &&
                Utils.getSubjectDNNameComponent(certificate, BCStyle.EmailAddress.getId()).size() > 0 &&
                SMIMEUtils.isSMIMEBRCertificate(certificate);
    }

}
