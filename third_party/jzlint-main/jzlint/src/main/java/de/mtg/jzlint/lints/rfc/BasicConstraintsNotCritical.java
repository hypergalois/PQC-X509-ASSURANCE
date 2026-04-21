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
 RFC 5280: 4.2.1.9
 Conforming CAs MUST include this extension in all CA certificates that contain
 public keys used to validate digital signatures on certificates and MUST mark
 the extension as critical in such certificates.  This extension MAY appear as a
 critical or non-critical extension in CA certificates that contain public keys
 used exclusively for purposes other than validating digital signatures on
 certificates.  Such CA certificates include ones that contain public keys used
 exclusively for validating digital signatures on CRLs and ones that contain key
 management public keys used with certificate.
 ************************************************/
@Lint(
        name = "e_basic_constraints_not_critical",
        description = "basicConstraints MUST appear as a critical extension",
        citation = "RFC 5280: 4.2.1.9",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class BasicConstraintsNotCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.isBasicConstraintsExtensionCritical(certificate)) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR, "Basic Constraints extension is marked as non-critical");
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isCA(certificate) && Utils.hasBasicConstraintsExtension(certificate);
    }
}
