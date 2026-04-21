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
 The freshest CRL extension identifies how delta CRL
 information is obtained. The extension MUST be marked
 as non-critical by conforming CAs. Further discussion
 of CRL management is contained in Section 5.
 ************************************************/

@Lint(
        name = "e_ext_freshest_crl_marked_critical",
        description = "Freshest CRL MUST be marked as non-critical by conforming CAs",
        citation = "RFC 5280: 4.2.1.15",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC3280)
public class ExtFreshestCrlMarkedCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.isExtensionCritical(certificate, Extension.freshestCRL.getId())) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.freshestCRL.getId());
    }
}
