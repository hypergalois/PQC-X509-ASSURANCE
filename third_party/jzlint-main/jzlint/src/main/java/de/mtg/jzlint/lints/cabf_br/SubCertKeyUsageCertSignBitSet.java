package de.mtg.jzlint.lints.cabf_br;

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
import de.mtg.jzlint.utils.Utils;

/**************************************************************************
 BRs: 7.1.2.3
 keyUsage (optional)
 If present, bit positions for keyCertSign and cRLSign MUST NOT be set.
 ***************************************************************************/

@Lint(
        name = "e_sub_cert_key_usage_cert_sign_bit_set",
        description = "Subscriber Certificate: keyUsage if present, bit positions for keyCertSign and cRLSign MUST NOT be set.",
        citation = "BRs: 7.1.2.3",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class SubCertKeyUsageCertSignBitSet implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());
        KeyUsage keyUsage = KeyUsage.getInstance(ASN1OctetString.getInstance(rawKeyUsage).getOctets());

        if (keyUsage.hasUsages(KeyUsage.keyCertSign)) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasKeyUsageExtension(certificate) && !Utils.isCA(certificate);
    }

}
