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
 BRs: 7.1.2.2g extkeyUsage (optional)
 For Subordinate CA Certificates to be Technically constrained in line with section 7.1.5, then either the value
 id-kp-serverAuth [RFC5280] or id-kp-clientAuth [RFC5280] or both values MUST be present.
 Other values MAY be present.
 If present, this extension SHOULD be marked non-critical.
 ************************************************/

@Lint(
        name = "w_sub_ca_eku_critical",
        description = "Subordinate CA certificate extkeyUsage extension should be marked non-critical if present",
        citation = "BRs: 7.1.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABV116Date)
public class SubCaEkuCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.isExtensionCritical(certificate, Extension.extendedKeyUsage.getId())) {
            return LintResult.of(Status.WARN);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubCA(certificate) && Utils.hasExtendedKeyUsageExtension(certificate);
    }

}
