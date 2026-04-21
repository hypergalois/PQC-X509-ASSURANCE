package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509CRL;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaCRLLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

/************************************************
 RFC 5280: 5.1.2.5
 Conforming CRL issuers MUST include the nextUpdate field in all CRLs.
 ************************************************/

@Lint(
        name = "e_crl_has_next_update",
        description = "Conforming CRL issuers MUST include the nextUpdate field in all CRLs.",
        citation = "RFC 5280: 5.1.2.5",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class CrlNextUpdateMandatory implements JavaCRLLint {

    @Override
    public LintResult execute(X509CRL crl) {
        if (crl.getNextUpdate() != null) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509CRL crl) {
        return true;
    }

}
