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
 Authority Information Access
 The authority information access extension indicates how to access
 information and services for the issuer of the certificate in which
 the extension appears. Information and services may include on-line
 validation services and CA policy data. (The location of CRLs is not
 specified in this extension; that information is provided by the
 cRLDistributionPoints extension.) This extension may be included in
 end entity or CA certificates. Conforming CAs MUST mark this extension
 as non-critical.
 ************************************************/
@Lint(
        name = "e_ext_aia_marked_critical",
        description = "Conforming e_ext_aia_marked_critical must mark the Authority Information Access extension as non-critical",
        citation = "RFC 5280: 4.2.2.1",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtAiaMarkedCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.isAuthorityInformationAccessExtensionCritical(certificate)) {
            return LintResult.of(Status.ERROR);
        } else {
            return LintResult.of(Status.PASS);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasAuthorityInformationAccessExtension(certificate);
    }

}
