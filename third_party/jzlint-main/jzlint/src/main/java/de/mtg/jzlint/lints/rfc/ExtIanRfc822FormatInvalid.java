package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;


/************************************************************************
 RFC 5280: 4.2.1.6
 When the issuerAltName extension contains an Internet mail address,
 the address MUST be stored in the rfc822Name.  The format of an
 rfc822Name is a "Mailbox" as defined in Section 4.1.2 of [RFC2821].
 A Mailbox has the form "Local-part@Domain".  Note that a Mailbox has
 no phrase (such as a common name) before it, has no comment (text
 surrounded in parentheses) after it, and is not surrounded by "{@literal <}" and
 "{@literal >}".  Rules for encoding Internet mail addresses that include
 internationalized domain names are specified in Section 7.5.
 ************************************************************************/

@Lint(
        name = "e_ext_ian_rfc822_format_invalid",
        description = "Email must not be surrounded with `<>`, and there MUST NOT be trailing comments in `()`",
        citation = "RFC 5280: 4.2.1.7",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtIanRfc822FormatInvalid implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawIAN = certificate.getExtensionValue(Extension.issuerAlternativeName.getId());

        try {
            List<GeneralName> emails = Utils.getEmails(rawIAN);

            for (GeneralName generalName : emails) {
                String email = generalName.getName().toString();

                if (email.contains(" ")) {
                    return LintResult.of(Status.ERROR);
                }

                if (email.startsWith("<") || email.endsWith(")")) {
                    return LintResult.of(Status.ERROR);
                }
            }

        } catch (IOException ex) {
            return LintResult.of(Status.FATAL);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.issuerAlternativeName.getId());
    }
}
