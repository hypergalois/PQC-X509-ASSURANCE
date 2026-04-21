package de.mtg.jlint.lints.smime;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

/**
 * 7.1.2.3 Subscriber certificates
 * b. cRLDistributionPoints (SHALL be present)
 * This extension SHOULD NOT be marked critical. It SHALL contain at least one
 * distributionPoint whose fullName value includes a GeneralName of type
 * uniformResourceIdentifier that includes a URI where the Issuing CA’s CRL can be
 * retrieved.
 */
@Lint(
        name = "w_smime_crldistributionpoints_extension_critical",
        description = "Check if a subscriber certificate has a critical cRLDistributionPoints extension",
        citation = "SMIME BR 7.1.2.3b",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SmimeCrlDistributionPointsExtensionCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {


        if (Utils.isExtensionCritical(certificate, Extension.cRLDistributionPoints.getId())) {
            return LintResult.of(Status.WARN);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return SMIMEUtils.isSMIMEBRSubscriberCertificate(certificate) && Utils.hasCRLDPExtension(certificate);
    }

}