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
        name = "e_rsa_other_key_usages",
        description = "Other bit positions SHALL NOT be set.",
        citation = "7.1.2.3.e",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class RsaOtherKeyUsages implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());
        KeyUsage keyUsage = KeyUsage.getInstance(ASN1OctetString.getInstance(rawKeyUsage).getOctets());

        if (!(keyUsage.hasUsages(KeyUsage.digitalSignature) || keyUsage.hasUsages(KeyUsage.keyEncipherment))) {
            byte[] rawValue = ASN1OctetString.getInstance(rawKeyUsage).getOctets();
            ASN1BitString asn1BitString = ASN1BitString.getInstance(rawValue);
            if (asn1BitString.intValue() == 0) {
                return LintResult.of(Status.NA);
            }
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        return Utils.isSubscriberCert(certificate) &&
                SMIMEUtils.isSMIMEBRCertificate(certificate) &&
                Utils.hasKeyUsageExtension(certificate) &&
                Utils.isPublicKeyRSA(certificate);
    }

}
