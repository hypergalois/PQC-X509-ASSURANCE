package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/*********************************************************
 RFC 5280: 4.2.1.1
 Conforming CAs MUST mark this extension as non-critical.
 **********************************************************/
@Lint(
        name = "e_ext_authority_key_identifier_critical",
        description = "The authority key identifier extension must be non-critical",
        citation = "RFC 5280: 4.2.1.1",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class ExtAuthorityKeyIdentifierCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.isAuthorityKeyIdentifierExtensionCritical(certificate)) {
            return LintResult.of(Status.ERROR);
        } else {
            return LintResult.of(Status.PASS);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasAuthorityKeyIdentifierExtension(certificate);
    }


}
