package de.mtg.jzlint.lints.cabf_smime_br;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;


/*************************************************************************
 7.1.4.2.1 Subject alternative name extension

 All Mailbox Addresses in the subject field or entries of type dirName of this extension SHALL be
 repeated as rfc822Name or otherName values of type id-on-SmtpUTF8Mailbox in this
 extension.

 7.1.4.2.2 Subject distinguished name fields

 h. Certificate Field: subject:emailAddress (1.2.840.113549.1.9.1) Contents: If present, the
 subject:emailAddress SHALL contain a single Mailbox Address as verified under
 Section 3.2.2.

 Combining these requirements, this lint checks for malformed email addresses in SAN entries
 covering the case of a non-single Mailbox Address.
 *************************************************************************/

@Lint(
        name = "e_single_email_if_present",
        description = "If present, the subject:emailAddress SHALL contain a single Mailbox Address. All Mailbox Addresses in the subject field SHALL be repeated as rfc822Name or otherName values of type id-on-SmtpUTF8Mailbox in SAN extension.",
        citation = "7.1.4.2.1 and 7.1.4.2.2.h",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SingleEmailIfPresent implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            List<String> emails = Utils.getEmails(certificate);

            for (String email : emails) {
                if (!SMIMEUtils.isValidEmailAddress(email)) {
                    return LintResult.of(Status.ERROR, String.format("san:emailAddress was present and contained an invalid email address (%s)", email));
                }
            }
            return LintResult.of(Status.PASS);
        } catch (IOException ex) {
            return LintResult.of(Status.FATAL);
        }
    }


    @Override
    public boolean checkApplies(X509Certificate certificate) {
        try {
            return Utils.isSubscriberCert(certificate) &&
                    Utils.getEmails(certificate).size() > 0 &&
                    SMIMEUtils.isSMIMEBRCertificate(certificate);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
