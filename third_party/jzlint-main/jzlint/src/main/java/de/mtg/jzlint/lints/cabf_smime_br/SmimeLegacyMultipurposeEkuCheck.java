package de.mtg.jzlint.lints.cabf_smime_br;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_smime_legacy_multipurpose_eku_check",
        description = "Strict/Multipurpose and Legacy: id-kp-emailProtection SHALL be present. Other values MAY be present. The values id-kp-serverAuth, id-kp-codeSigning, id-kp-timeStamping, and anyExtendedKeyUsage values SHALL NOT be present.",
        citation = "SMIME BRs: 7.1.2.3.f",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SmimeLegacyMultipurposeEkuCheck implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (!Utils.hasExtendedKeyUsageExtension(certificate)) {
            return LintResult.of(Status.ERROR, "id-kp-emailProtection SHALL be present");
        }

        byte[] rawEKU = certificate.getExtensionValue(Extension.extendedKeyUsage.getId());
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(ASN1OctetString.getInstance(rawEKU).getOctets());

        if (!extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection)) {
            return LintResult.of(Status.ERROR, "id-kp-emailProtection SHALL be present");
        }
        if (extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth)) {
            return LintResult.of(Status.ERROR, "id-kp-serverAuth value SHALL NOT be present");
        }
        if (extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_timeStamping)) {
            return LintResult.of(Status.ERROR, "id-kp-timeStamping value SHALL NOT be present");
        }
        if (extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_codeSigning)) {
            return LintResult.of(Status.ERROR, "id-kp-codeSigning value SHALL NOT be present");
        }
        if (extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.anyExtendedKeyUsage)) {
            return LintResult.of(Status.ERROR, "anyExtendedKeyUsage value SHALL NOT be present");
        }

        return LintResult.of(Status.PASS);
    }

    // CheckApplies returns true if the provided certificate contains one-or-more of the following SMIME BR policy identifiers:
    //   - Mailbox Validated Legacy
    //   - Mailbox Validated Multipurpose
    //   - Organization Validated Legacy
    //   - Organization Validated Multipurpose
    //   - Sponsor Validated Legacy
    //   - Sponsor Validated Multipurpose
    //   - Individual Validated Legacy
    //   - Individual Validated Multipurpose
    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return (SMIMEUtils.isLegacySMIMECertificate(certificate)
                || SMIMEUtils.isMultipurposeSMIMECertificate(certificate)) && Utils.isSubscriberCert(certificate);
    }

}
