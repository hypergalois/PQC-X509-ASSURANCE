package de.mtg.jlint.lints.rfc;

import java.security.cert.X509CRL;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaCRLLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

/**
 * When CRLs are issued,
 * the CRLs MUST be version 2 CRLs, include the date by which the next
 * CRL will be issued in the nextUpdate field (Section 5.1.2.5), include
 * the CRL number extension (Section 5.2.3), and include the authority
 * key identifier extension (Section 5.2.1).
 */


@Lint(
        name = "e_crl_version_value_is_two",
        description = "Check if the version of the CRL is 2 (the integer value is 1).",
        citation = "RFC 5280, Sec. 5",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class CrlVersionValueIsTwo implements JavaCRLLint {

    @Override
    public LintResult execute(X509CRL crl) {

        if (crl.getVersion() == 2) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR, String.format("CRL is not version 2 but it is version %d", crl.getVersion()));
    }

    @Override
    public boolean checkApplies(X509CRL crl) {
        return true;
    }

}
