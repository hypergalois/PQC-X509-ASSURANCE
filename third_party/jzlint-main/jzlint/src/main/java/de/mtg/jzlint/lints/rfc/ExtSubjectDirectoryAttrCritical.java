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
 RFC 5280: 4.2.1.8
 The subject directory attributes extension is used to convey
 identification attributes (e.g., nationality) of the subject.  The
 extension is defined as a sequence of one or more attributes.
 Conforming CAs MUST mark this extension as non-critical.
 ************************************************/

@Lint(
        name = "e_ext_subject_directory_attr_critical",
        description = "Conforming CAs MUST mark the Subject Directory Attributes extension as not critical",
        citation = "RFC 5280: 4.2.1.8",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtSubjectDirectoryAttrCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.isExtensionCritical(certificate, Extension.subjectDirectoryAttributes.getId())) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.subjectDirectoryAttributes.getId());
    }
}
