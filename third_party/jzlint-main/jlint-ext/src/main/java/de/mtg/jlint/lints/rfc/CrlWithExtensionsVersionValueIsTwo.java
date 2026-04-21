package de.mtg.jlint.lints.rfc;

import java.security.cert.X509CRL;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaCRLLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.CRLUtils;

/**
 * 5.1.2.1.  Version
 * <p>
 * This optional field describes the version of the encoded CRL. When
 * extensions are used, as required by this profile, this field MUST be
 * present and MUST specify version 2 (the integer value is 1).
 */

@Lint(
        name = "e_crl_with_extensions_version_value_is_two",
        description = "Check if the version of the CRL is 2 (the integer value is 1) when extensions are used.",
        citation = "RFC 5280, Sec. 5.1.2.1",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class CrlWithExtensionsVersionValueIsTwo implements JavaCRLLint {

    @Override
    public LintResult execute(X509CRL crl) {

        if (CRLUtils.hasExtensions(crl)) {
            if (crl.getVersion() == 2) {
                return LintResult.of(Status.PASS);
            }
            return LintResult.of(Status.ERROR, String.format("CRL contains extensions but it is version %d", crl.getVersion()));
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509CRL crl) {
        return true;
    }

}
