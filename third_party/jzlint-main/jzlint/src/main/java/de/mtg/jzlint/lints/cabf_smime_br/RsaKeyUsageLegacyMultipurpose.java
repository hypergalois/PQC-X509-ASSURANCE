package de.mtg.jzlint.lints.cabf_smime_br;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_rsa_key_usage_legacy_multipurpose",
        description = "For signing only, bit positions SHALL be set for digitalSignature and MAY be set for nonRepudiation. For key management only, bit positions SHALL be set for keyEncipherment and MAY be set for dataEncipherment. For dual use, bit positions SHALL be set for digitalSignature and keyEncipherment and MAY be set for nonRepudiation and dataEncipherment.",
        citation = "7.1.2.3.e",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class RsaKeyUsageLegacyMultipurpose implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());
        byte[] rawValue = ASN1OctetString.getInstance(rawKeyUsage).getOctets();
        KeyUsage keyUsage = KeyUsage.getInstance(ASN1OctetString.getInstance(rawKeyUsage).getOctets());

        boolean isSigningOnly = false;
        boolean isKeyManagementOnly = false;
        boolean isDualUse = false;


        if (keyUsage.hasUsages(KeyUsage.digitalSignature) && keyUsage.hasUsages(KeyUsage.keyEncipherment)) {
            isDualUse = true;
        } else if (keyUsage.hasUsages(KeyUsage.digitalSignature) && !keyUsage.hasUsages(KeyUsage.keyEncipherment)) {
            isSigningOnly = true;
        } else if (!keyUsage.hasUsages(KeyUsage.digitalSignature) && keyUsage.hasUsages(KeyUsage.keyEncipherment)) {
            isKeyManagementOnly = true;
        }

        if (isSigningOnly) {
            if (EcpublickeyKeyUsages.checkKUs(rawValue, KeyUsage.digitalSignature, KeyUsage.nonRepudiation)) {
                return LintResult.of(Status.ERROR);
            }
        } else if (isKeyManagementOnly) {
            if (EcpublickeyKeyUsages.checkKUs(rawValue, KeyUsage.keyEncipherment, KeyUsage.dataEncipherment)) {
                return LintResult.of(Status.ERROR);
            }
        } else if (isDualUse) {
            if (EcpublickeyKeyUsages.checkKUs(rawValue,
                    KeyUsage.digitalSignature,
                    KeyUsage.nonRepudiation,
                    KeyUsage.keyEncipherment,
                    KeyUsage.dataEncipherment)) {
                return LintResult.of(Status.ERROR);
            }
        } else {
            return LintResult.of(Status.NA);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        if (!(
                Utils.isSubscriberCert(certificate) &&
                        (SMIMEUtils.isLegacySMIMECertificate(certificate) || SMIMEUtils.isMultipurposeSMIMECertificate(certificate)) &&
                        Utils.hasKeyUsageExtension(certificate)
        )) {
            return false;
        }

        return Utils.isPublicKeyRSA(certificate);
    }

}
