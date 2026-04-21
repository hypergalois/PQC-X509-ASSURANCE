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

/************************************************
 RFC 8813: 3.  Updates to Section 3
 If the keyUsage extension is present in a certificate that indicates
 id-ecPublicKey in SubjectPublicKeyInfo, then the following values
 MUST NOT be present:
 keyEncipherment; and
 dataEncipherment.
 ************************************************/

@Lint(
        name = "e_ecdsa_allowed_ku",
        description = "Key usage values keyEncipherment or dataEncipherment MUST NOT be present in certificates with ECDSA public keys",
        citation = "RFC 8813 Section 3",
        source = Source.RFC8813,
        effectiveDate = EffectiveDate.RFC8813)
public class EcdsaAllowedKu implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());
        KeyUsage keyUsage = KeyUsage.getInstance(ASN1OctetString.getInstance(rawKeyUsage).getOctets());
        StringBuilder stringBuilder = new StringBuilder();

        if (keyUsage.hasUsages(KeyUsage.keyEncipherment)) {
            stringBuilder.append("keyEncipherment");
        }

        if (keyUsage.hasUsages(KeyUsage.dataEncipherment)) {
            stringBuilder.append(", dataEncipherment");
        }

        if (!stringBuilder.toString().isEmpty()) {
            return LintResult.of(Status.ERROR, String.format("Certificate contains invalid key usage(s): %s", stringBuilder.toString()));
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasKeyUsageExtension(certificate) && Utils.isPublicKeyECC(certificate);
    }
}
