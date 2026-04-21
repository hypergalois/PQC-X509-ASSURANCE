package de.mtg.jzlint.lints.cabf_br;

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
 BRs: 7.1.2.1b
 This extension MUST be present and MUST be marked critical. Bit positions for keyCertSign and cRLSign MUST be set.
 If the Root CA Private Key is used for signing OCSP responses, then the digitalSignature bit MUST be set.
 ************************************************/

@Lint(
        name = "e_ca_key_usage_not_critical",
        description = "Root and Subordinate CA certificate keyUsage extension MUST be marked as critical",
        citation = "BRs: 7.1.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class CaKeyUsageNotCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (!Utils.isExtensionCritical(certificate, Extension.keyUsage.getId())) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isCA(certificate) && Utils.hasKeyUsageExtension(certificate);
    }


}
