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
 * a. certificatePolicies (SHALL be present)
 * This extension SHOULD NOT be marked critical. It SHALL include exactly one of the
 * reserved policyIdentifiers listed in Section 7.1.6.1, and MAY contain one or more
 * identifiers documented by the CA in its CP and/or CPS.
 * If the value of this extension includes a PolicyInformation which contains a qualifier of
 * type id-qt-cps (OID: 1.3.6.1.5.5.7.2.1), then the value of the qualifier SHALL be a HTTP or
 * HTTPS URL for the Issuing CA’s CP and/or CPS, Relying Party Agreement, or other pointer to
 * online policy information provided by the Issuing CA. If a qualifier of type id-qt-unotice
 * (OID: 1.3.6.1.5.5.7.2.2) is included, then it SHALL contain explicitText and SHALL NOT
 * contain noticeRef.
 */
@Lint(
        name = "w_smime_certificate_policies_extension_critical",
        description = "Check if a subscriber certificate has a critical certificatePolicies extension",
        citation = "SMIME BR 7.1.2.3a",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SmimeCertificatePoliciesExtensionCritical implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        if (Utils.isExtensionCritical(certificate, Extension.certificatePolicies.getId())) {
            return LintResult.of(Status.WARN);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return SMIMEUtils.isSMIMEBRSubscriberCertificate(certificate) && Utils.hasCertificatePoliciesExtension(certificate);
    }

}