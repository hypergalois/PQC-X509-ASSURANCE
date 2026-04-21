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
 Issuer Alternative Name
 As with Section 4.2.1.6, this extension is used to
 associate Internet style identities with the certificate
 issuer. Issuer alternative name MUST be encoded as in 4.2.1.6.
 Issuer alternative names are not processed as part of the
 certification path validation algorithm in Section 6.
 (That is, issuer alternative names are not used in
 name chaining and name constraints are not enforced.)
 Where present, conforming CAs SHOULD mark this extension
 as non-critical.
 ************************************************/

@Lint(
        name = "w_ext_ian_critical",
        description = "Issuer alternate name should be marked as non-critical",
        citation = "RFC 5280: 4.2.1.7",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtIanCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.isExtensionCritical(certificate, Extension.issuerAlternativeName.getId())) {
            return LintResult.of(Status.WARN);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.issuerAlternativeName.getId());
    }
}
