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
 RFC 5280: 4.1.2.4
 The issuer field identifies the entity that has signed and issued the
 certificate.  The issuer field MUST contain a non-empty distinguished
 name (DN).  The issuer field is defined as the X.501 type Name
 [X.501].
 ************************************************/

@Lint(
        name = "e_issuer_field_empty",
        description = "Certificate issuer field MUST NOT be empty and must have a non-empty distinguished name",
        citation = "RFC 5280: 4.1.2.4",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class IssuerFieldEmpty implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.isIssuerDNEmpty(certificate)) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }
}
