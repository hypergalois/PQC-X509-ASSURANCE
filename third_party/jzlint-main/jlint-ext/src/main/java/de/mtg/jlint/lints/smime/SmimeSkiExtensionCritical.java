package de.mtg.jlint.lints.smime;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/**
 * 7.1.2.3 Subscriber certificates
 * n. subjectKeyIdentifier (SHOULD be present)
 * This extension SHALL NOT be marked critical. It SHOULD contain a value that is derived
 * from the Public Key included in the Subscriber Certificate.
 *
 */
@Lint(
        name = "e_smime_ski_extension_critical",
        description = "Check if a subscriber certificate has a critical subject key identifier extension",
        citation = "SMIME BR 7.1.2.3n",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SmimeSkiExtensionCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.isExtensionCritical(certificate, Extension.subjectKeyIdentifier.getId())) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) && Utils.hasExtension(certificate, Extension.subjectKeyIdentifier.getId());
    }

}
