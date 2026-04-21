package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 RFC 5280: 4.2.1.6
 Further, if the only subject identity included in the certificate is
 an alternative name form (e.g., an electronic mail address), then the
 subject distinguished name MUST be empty (an empty sequence), and the
 subjectAltName extension MUST be present.  If the subject field
 contains an empty sequence, then the issuing CA MUST include a
 subjectAltName extension that is marked as critical.  When including
 the subjectAltName extension in a certificate that has a non-empty
 subject distinguished name, conforming CAs SHOULD mark the
 subjectAltName extension as non-critical.
 ************************************************/

/************************************************
 RFC 5280: 4.2.1.6
 Further, if the only subject identity included in the certificate is
 an alternative name form (e.g., an electronic mail address), then the
 subject distinguished name MUST be empty (an empty sequence), and the
 subjectAltName extension MUST be present.  If the subject field
 contains an empty sequence, then the issuing CA MUST include a
 subjectAltName extension that is marked as critical.  When including
 the subjectAltName extension in a certificate that has a non-empty
 subject distinguished name, conforming CAs SHOULD mark the
 subjectAltName extension as non-critical.
 ************************************************/

@Lint(
        name = "e_ext_san_not_critical_without_subject",
        description = "If there is an empty subject field, then the SAN extension MUST be critical",
        citation = "RFC 5280: 4.2.1.6",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtSanNotCriticalWithoutSubject implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        ASN1Sequence subjectDNSequence = ASN1Sequence.getInstance(certificate.getSubjectX500Principal().getEncoded());

        if (subjectDNSequence.size() == 0 && !Utils.isExtensionCritical(certificate, Extension.subjectAlternativeName.getId())) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.subjectAlternativeName.getId());
    }
}
