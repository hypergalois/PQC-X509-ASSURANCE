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

// "When present, conforming CAs SHOULD mark this extension as critical."

@Lint(
        name = "w_ext_key_usage_not_critical",
        description = "The keyUsage extension SHOULD be critical",
        citation = "RFC 5280: 4.2.1.3",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtKeyUsageNotCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.isExtensionCritical(certificate, Extension.keyUsage.getId())) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.WARN);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasKeyUsageExtension(certificate);
    }
}
