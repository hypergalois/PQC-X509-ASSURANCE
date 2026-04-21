package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 RFC 5280: 4.2.1.3
 Conforming CAs MUST include this extension in certificates that
 contain public keys that are used to validate digital signatures on
 other public key certificates or CRLs.  When present, conforming CAs
 SHOULD mark this extension as critical.
 ************************************************/

@Lint(
        name = "e_ca_key_usage_missing",
        description = "Root and Subordinate CA certificate keyUsage extension MUST be present",
        citation = "BRs: 7.1.2.1, RFC 5280: 4.2.1.3",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.RFC3280)
public class CaKeyUsageMissing implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (!Utils.hasKeyUsageExtension(certificate)) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isCA(certificate);
    }


}
