package de.mtg.jzlint.lints.cabf_smime_br;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1BitString;
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
        name = "e_ecpublickey_key_usages",
        description = "For signing only, bit positions SHALL be set for digitalSignature and MAY be set for nonRepudiation. For key management only, bit positions SHALL be set for keyEncipherment. For dual use, bit positions SHALL be set for digitalSignature and keyEncipherment and MAY be set for nonRepudiation.",
        citation = "7.1.2.3.e",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class EcpublickeyKeyUsages implements JavaLint {

    private static final int ALL_SET = KeyUsage.encipherOnly | // 1
            KeyUsage.cRLSign |// 2
            KeyUsage.keyCertSign |// 4
            KeyUsage.keyAgreement |// 8
            KeyUsage.dataEncipherment | // 16
            KeyUsage.keyEncipherment | //32
            KeyUsage.nonRepudiation | // 64
            KeyUsage.digitalSignature | // 128
            KeyUsage.decipherOnly; //32768

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());
        byte[] rawValue = ASN1OctetString.getInstance(rawKeyUsage).getOctets();
        KeyUsage keyUsage = KeyUsage.getInstance(ASN1OctetString.getInstance(rawKeyUsage).getOctets());

        boolean isSigningOnly = false;
        boolean isKeyManagementOnly = false;
        boolean isDualUse = false;


        if (keyUsage.hasUsages(KeyUsage.digitalSignature) && keyUsage.hasUsages(KeyUsage.keyAgreement)) {
            isDualUse = true;
        } else if (keyUsage.hasUsages(KeyUsage.digitalSignature) && !keyUsage.hasUsages(KeyUsage.keyAgreement)) {
            isSigningOnly = true;
        } else if (!keyUsage.hasUsages(KeyUsage.digitalSignature) && keyUsage.hasUsages(KeyUsage.keyAgreement)) {
            isKeyManagementOnly = true;
        }

        if (isSigningOnly) {
            if (checkKUs(rawValue, KeyUsage.digitalSignature, KeyUsage.nonRepudiation)) {
                return LintResult.of(Status.ERROR);
            }
        } else if (isKeyManagementOnly) {
            if (checkKUs(rawValue, KeyUsage.keyAgreement, KeyUsage.encipherOnly, KeyUsage.decipherOnly)) {
                return LintResult.of(Status.ERROR);
            }
        } else if (isDualUse) {
            if (checkKUs(rawValue,
                    KeyUsage.digitalSignature,
                    KeyUsage.nonRepudiation,
                    KeyUsage.keyAgreement,
                    KeyUsage.encipherOnly,
                    KeyUsage.decipherOnly)) {
                return LintResult.of(Status.ERROR);
            }
        } else {
            return LintResult.of(Status.NA);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        return Utils.isSubscriberCert(certificate) &&
                SMIMEUtils.isSMIMEBRCertificate(certificate) &&
                Utils.hasKeyUsageExtension(certificate) &&
                Utils.isPublicKeyECC(certificate);
    }

    protected static boolean checkKUs(byte[] rawValue, int... keyUsages) {

        ASN1BitString asn1BitString = ASN1BitString.getInstance(rawValue);

        int check = 0;
        for (int keyUsageValue : keyUsages) {
            check = check | keyUsageValue;
        }

        return (asn1BitString.intValue() & (ALL_SET ^ check)) != 0;
    }

}
