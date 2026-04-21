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
 The CRL distribution points extension identifies
 how CRL information is obtained. The extension
 SHOULD be non-critical, but this profile RECOMMENDS
 support for this extension by CAs and applications.
 ************************************************/

@Lint(
        name = "w_ext_crl_distribution_marked_critical",
        description = "If included, the CRL Distribution Points extension SHOULD NOT be marked critical",
        citation = "RFC 5280: 4.2.1.13",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtCrlDistributionMarkedCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.isCRLDPExtensionCritical(certificate)) {
            return LintResult.of(Status.WARN);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasCRLDPExtension(certificate);
    }
}
