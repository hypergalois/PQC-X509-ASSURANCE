package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 The subject information access extension indicates
 how to access information and services for the subject
 of the certificate in which the extension appears. When
 the subject is a CA, information and services may include
 certificate validation services and CA policy data.
 When the subject is an end entity, the information
 describes the type of services offered and how to
 access them. In this case, the contents of this extension
 are defined in the protocol specifications for the
 supported services. This extension may be included
 in end entity or CA certificates. Conforming CAs
 MUST mark this extension as non-critical.
 ************************************************/


@Lint(
        name = "e_subject_info_access_marked_critical",
        description = "Conforming CAs MUST mark the Subject Info Access extension as non-critical",
        citation = "RFC 5280: 4.2.2.2",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC3280)
public class SubjectInfoAccessMarkedCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.isExtensionCritical(certificate, Extension.subjectInfoAccess.getId())) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.subjectInfoAccess.getId());
    }


}
