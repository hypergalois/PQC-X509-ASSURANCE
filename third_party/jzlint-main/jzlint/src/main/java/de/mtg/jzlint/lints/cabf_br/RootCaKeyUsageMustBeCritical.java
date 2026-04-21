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

@Lint(
        name = "e_root_ca_key_usage_must_be_critical",
        description = "Root CA certificates MUST have Key Usage Extension marked critical",
        citation = "BRs: 7.1.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.RFC2459)
public class RootCaKeyUsageMustBeCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (!Utils.isExtensionCritical(certificate, Extension.keyUsage.getId())) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isRootCA(certificate);
    }


}
