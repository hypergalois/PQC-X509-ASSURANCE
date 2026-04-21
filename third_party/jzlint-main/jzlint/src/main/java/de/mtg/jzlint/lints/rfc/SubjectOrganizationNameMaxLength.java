package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 RFC 5280: A.1
 * In this Appendix, there is a list of upperbounds
 for fields in a x509 Certificate. *
 ub-organization-name INTEGER ::= 64
 ************************************************/

@Lint(
        name = "e_subject_organization_name_max_length",
        description = "The 'Organization Name' field of the subject MUST be less than 65 characters",
        citation = "RFC 5280: A.1",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class SubjectOrganizationNameMaxLength implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        return SubjectOrganizationNameMaxLength.isSubjectComponentGreaterThan(certificate, X509ObjectIdentifiers.organization.getId(), 64);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.organization.getId()).isEmpty();
    }

    protected static LintResult isSubjectComponentGreaterThan(X509Certificate certificate, String oid, int length) {
        List<AttributeTypeAndValue> subjectNameComponent = Utils.getSubjectDNNameComponent(certificate, oid);

        for (AttributeTypeAndValue attributeTypeAndValue : subjectNameComponent) {
            if (attributeTypeAndValue.getValue().toString().length() > length) {
                return LintResult.of(Status.ERROR);
            }
        }

        return LintResult.of(Status.PASS);
    }
}
