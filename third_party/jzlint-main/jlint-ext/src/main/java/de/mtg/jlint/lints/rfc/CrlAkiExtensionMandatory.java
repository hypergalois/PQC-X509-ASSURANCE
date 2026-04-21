package de.mtg.jlint.lints.rfc;

import java.security.cert.X509CRL;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaCRLLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.CRLUtils;

/**
 * Conforming CAs are not required to issue CRLs if other revocation or
 * certificate status mechanisms are provided.  When CRLs are issued,
 * the CRLs MUST be version 2 CRLs, include the date by which the next
 * CRL will be issued in the nextUpdate field (Section 5.1.2.5), include
 * the CRL number extension (Section 5.2.3), and include the authority
 * key identifier extension (Section 5.2.1).
 */

@Lint(
        name = "e_crl_aki_extension_mandatory",
        description = "Check if the CRL contains the authority key identifier extension",
        citation = "RFC 5280, Sec. 5",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class CrlAkiExtensionMandatory implements JavaCRLLint {

    @Override
    public LintResult execute(X509CRL crl) {
        if (CRLUtils.hasExtension(crl, Extension.authorityKeyIdentifier.getId())) {
            return LintResult.of(Status.PASS);
        }

        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509CRL crl) {
        return true;
    }

}
