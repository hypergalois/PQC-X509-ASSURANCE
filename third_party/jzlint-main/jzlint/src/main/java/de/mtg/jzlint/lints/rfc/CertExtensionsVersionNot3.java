package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 4.1.2.1.  Version
 This field describes the version of the encoded certificate. When
 extensions are used, as expected in this profile, version MUST be 3
 (value is 2). If no extensions are present, but a UniqueIdentifier
 is present, the version SHOULD be 2 (value is 1); however, the version
 MAY be 3.  If only basic fields are present, the version SHOULD be 1
 (the value is omitted from the certificate as the default value);
 however, the version MAY be 2 or 3.
 Implementations SHOULD be prepared to accept any version certificate.
 At a minimum, conforming implementations MUST recognize version 3 certificates.
 4.1.2.9.  Extensions
 This field MUST only appear if the version is 3 (Section 4.1.2.1).
 If present, this field is a SEQUENCE of one or more certificate
 extensions. The format and content of certificate extensions in the
 Internet PKI are defined in Section 4.2.
 ************************************************/
@Lint(
        name = "e_cert_extensions_version_not_3",
        description = "The extensions field MUST only appear in version 3 certificates",
        citation = "RFC 5280: 4.1.2.9",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class CertExtensionsVersionNot3 implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (certificate.getVersion() != 3 && Utils.hasExtensions(certificate)) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }
}
