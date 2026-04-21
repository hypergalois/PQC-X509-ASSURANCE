package de.mtg.jlint.lints.rfc;

import java.security.cert.X509CRL;
import java.util.function.Predicate;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaCRLLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.CRLUtils;

/**
 * This section defines the use of the Authority Information Access
 * extension in a CRL.  The syntax and semantics defined in Section
 * 4.2.2.1 for the certificate extension are also used for the CRL
 * extension.
 * <p>
 * This CRL extension MUST be marked as non-critical.
 */

@Lint(
        name = "e_crl_aia_extension_non_critical",
        description = "Check if the CRL contains a non-critical Authority Information Access extension",
        citation = "RFC 5280, Sec. 5.2.7",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class CrlAiaExtensionNonCritical implements JavaCRLLint {

    @Override
    public LintResult execute(X509CRL crl) {

        Predicate<String> oidEquals = oid -> oid.equals(Extension.authorityInfoAccess.getId());
        boolean found = crl.getCriticalExtensionOIDs().stream().anyMatch(oidEquals);

        if (found) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);

    }

    @Override
    public boolean checkApplies(X509CRL crl) {
        return CRLUtils.hasExtension(crl, Extension.authorityInfoAccess.getId());
    }

}
