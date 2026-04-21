package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

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
 RFC 3279: 2.3.1  RSA Keys
 If the keyUsage extension is present in a CA or CRL issuer
 certificate which conveys an RSA public key, any combination of the
 following values MAY be present:
 digitalSignature;
 nonRepudiation;
 keyEncipherment;
 dataEncipherment;
 keyCertSign; and
 cRLSign.
 However, this specification RECOMMENDS that if keyCertSign or cRLSign
 is present, both keyEncipherment and dataEncipherment SHOULD NOT be
 present.
 ************************************************/
@Lint(
        name = "e_rsa_allowed_ku_no_encipherment_ca",
        description = "If Key usage value keyCertSign or cRLSign is present in a CA certificate both keyEncipherment and dataEncipherment SHOULD NOT be present",
        citation = "RFC 3279: 2.3.1",
        source = Source.RFC3279,
        effectiveDate = EffectiveDate.RFC3279)
public class RsaAllowedKuNoEnciphermentCa implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());
        KeyUsage keyUsage = KeyUsage.getInstance(ASN1OctetString.getInstance(rawKeyUsage).getOctets());

        List<String> disallowedKUs = new ArrayList<>();
        if (keyUsage.hasUsages(KeyUsage.keyCertSign) || keyUsage.hasUsages(KeyUsage.cRLSign)) {
            checkKeyUsage(keyUsage, disallowedKUs, KeyUsage.keyEncipherment, "keyEncipherment");
            checkKeyUsage(keyUsage, disallowedKUs, KeyUsage.dataEncipherment, "dataEncipherment");
        }

        if (!disallowedKUs.isEmpty()) {
            return LintResult.of(Status.ERROR, "CA certificate with an RSA key and key usage keyCertSign and/or cRLSign has additionally keyEncipherment and/or dataEncipherment key usage");
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasKeyUsageExtension(certificate) && Utils.isPublicKeyRSA(certificate) && Utils.isCA(certificate);
    }

    private void checkKeyUsage(KeyUsage keyUsage, List<String> disallowedKUs, int disallowedKU, String dissalowedKUString) {
        if (keyUsage.hasUsages(disallowedKU)) {
            disallowedKUs.add(dissalowedKUString);
        }
    }
}
