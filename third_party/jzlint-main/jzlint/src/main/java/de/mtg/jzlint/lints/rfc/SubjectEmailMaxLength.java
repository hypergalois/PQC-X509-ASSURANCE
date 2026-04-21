package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.style.BCStyle;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.utils.Utils;


/************************************************
 RFC 5280: A.1
 * In this Appendix, there is a list of upperbounds
 for fields in a x509 Certificate. *
 ub-emailaddress-length INTEGER ::= 128
 The ASN.1 modules in Appendix A are unchanged from RFC 3280, except
 that ub-emailaddress-length was changed from 128 to 255 in order to
 align with PKCS #9 [RFC2985].
 ub-emailaddress-length INTEGER ::= 255
 ************************************************/

@Lint(
        name = "e_subject_email_max_length",
        description = "The 'Email' field of the subject MUST be less than 256 characters",
        citation = "RFC 5280: A.1",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class SubjectEmailMaxLength implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return SubjectOrganizationNameMaxLength.isSubjectComponentGreaterThan(certificate, BCStyle.EmailAddress.getId(), 255);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.getSubjectDNNameComponent(certificate, BCStyle.EmailAddress.getId()).isEmpty();
    }

}
