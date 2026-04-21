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

/**********************************************************************
 To facilitate certification path construction, this extension MUST
 appear in all conforming CA certificates, that is, all certificates
 including the basic constraints extension (Section 4.2.1.9) where the
 value of cA is TRUE.  In conforming CA certificates, the value of the
 subject key identifier MUST be the value placed in the key identifier
 field of the authority key identifier extension (Section 4.2.1.1) of
 certificates issued by the subject of this certificate.  Applications
 are not required to verify that key identifiers match when performing
 certification path validation.
 ...
 For end entity certificates, the subject key identifier extension provides
 a means for identifying certificates containing the particular public key
 used in an application. Where an end entity has obtained multiple certificates,
 especially from multiple CAs, the subject key identifier provides a means to
 quickly identify the set of certificates containing a particular public key.
 To assist applications in identifying the appropriate end entity certificate,
 this extension SHOULD be included in all end entity certificates.
 **********************************************************************/

@Lint(
        name = "w_ext_subject_key_identifier_missing_sub_cert",
        description = "Sub certificates SHOULD include Subject Key Identifier in end entity certs",
        citation = "RFC 5280: 4.2 & 4.2.1.2",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtSubjectKeyIdentifierMissingSubCert implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (!Utils.hasExtension(certificate, Extension.subjectKeyIdentifier.getId())) {
            return LintResult.of(Status.WARN);
        } else {
            return LintResult.of(Status.PASS);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.isCA(certificate);
    }

}
