package de.mtg.jzlint.lints.rfc;

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

@Lint(
        name = "n_ecdsa_ee_invalid_ku",
        description = "ECDSA end-entity certificates MAY have key usages: digitalSignature, nonRepudiation and keyAgreement",
        citation = "RFC 5480 Section 3",
        source = Source.RFC5480,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class EcdsaEeInvalidKu implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());

        KeyUsage keyUsage = KeyUsage.getInstance(ASN1OctetString.getInstance(rawKeyUsage).getOctets());

        if (keyUsage.hasUsages(KeyUsage.cRLSign) ||
                keyUsage.hasUsages(KeyUsage.dataEncipherment) ||
                keyUsage.hasUsages(KeyUsage.decipherOnly) ||
                keyUsage.hasUsages(KeyUsage.encipherOnly) ||
                keyUsage.hasUsages(KeyUsage.keyCertSign) ||
                keyUsage.hasUsages(KeyUsage.keyEncipherment)) {
            return LintResult.of(Status.NOTICE);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) && Utils.hasKeyUsageExtension(certificate) && Utils.isPublicKeyECC(certificate);
    }
}
