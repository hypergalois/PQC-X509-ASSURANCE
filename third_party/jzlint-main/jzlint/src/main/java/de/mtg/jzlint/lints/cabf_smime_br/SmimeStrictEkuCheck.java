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
        name = "e_smime_strict_eku_check",
        description = "Strict: id-kp-emailProtection SHALL be present.  Other values SHALL NOT be present",
        citation = "SMIME BRs: 7.1.2.3.f",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SmimeStrictEkuCheck implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (!Utils.hasExtendedKeyUsageExtension(certificate)) {
            return LintResult.of(Status.ERROR, "id-kp-emailProtection SHALL be present for strict validated.");
        }

        byte[] rawEKU = certificate.getExtensionValue(Extension.extendedKeyUsage.getId());
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(ASN1OctetString.getInstance(rawEKU).getOctets());

        KeyPurposeId[] usages = extendedKeyUsage.getUsages();

        for (KeyPurposeId keyPurposeId : usages) {
            if (!keyPurposeId.getId().equalsIgnoreCase(KeyPurposeId.id_kp_emailProtection.getId())) {
                return LintResult.of(Status.ERROR, "Found other extended key usages than id-kp-emailProtection for strict validated.");
            }
        }

        if (!extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection)) {
            return LintResult.of(Status.ERROR, "id-kp-emailProtection SHALL be present for strict validated");
        }

        return LintResult.of(Status.PASS);
    }

    // CheckApplies returns true if the provided certificate contains one-or-more of the following SMIME BR policy identifiers:
    //   - Mailbox Validated Strict
    //   - Organization Validated Strict
    //   - Sponsor Validated Strict
    //   - Individual Validated Strict
    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) && SMIMEUtils.isStrictSMIMECertificate(certificate);
    }

}
