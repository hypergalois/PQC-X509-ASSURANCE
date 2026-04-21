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


/**********************************************************
 RFC 5280: 4.2.1.2
 Conforming CAs MUST mark this extension as non-critical.
 **********************************************************/

@Lint(
        name = "e_ext_subject_key_identifier_critical",
        description = "The subject key identifier extension MUST be non-critical",
        citation = "RFC 5280: 4.2.1.2",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtSubjectKeyIdentifierCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.isExtensionCritical(certificate, Extension.subjectKeyIdentifier.getId())) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.subjectKeyIdentifier.getId());
    }
}
