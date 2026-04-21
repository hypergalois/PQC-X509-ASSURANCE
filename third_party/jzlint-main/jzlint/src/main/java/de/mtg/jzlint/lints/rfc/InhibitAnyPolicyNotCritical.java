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
 4.2.1.14.  Inhibit anyPolicy
 The inhibit anyPolicy extension can be used in certificates issued to CAs.
 The inhibit anyPolicy extension indicates that the special anyPolicy OID,
 with the value { 2 5 29 32 0 }, is not considered an explicit match for other
 certificate policies except when it appears in an intermediate self-issued
 CA certificate. The value indicates the number of additional non-self-issued
 certificates that may appear in the path before anyPolicy is no longer permitted.
 For example, a value of one indicates that anyPolicy may be processed in
 certificates issued by the subject of this certificate, but not in additional
 certificates in the path.
 Conforming CAs MUST mark this extension as critical.
 ************************************************/

@Lint(
        name = "e_inhibit_any_policy_not_critical",
        description = "CAs MUST mark the inhibitAnyPolicy extension as critical",
        citation = "RFC 5280: 4.2.1.14",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC3280)
public class InhibitAnyPolicyNotCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.isExtensionCritical(certificate, Extension.inhibitAnyPolicy.getId())) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.inhibitAnyPolicy.getId());
    }
}
