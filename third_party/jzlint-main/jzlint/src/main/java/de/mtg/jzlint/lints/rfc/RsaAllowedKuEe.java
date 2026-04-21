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
 If the keyUsage extension is present in an end entity certificate
 which conveys an RSA public key, any combination of the following
 values MAY be present:
 digitalSignature;
 nonRepudiation;
 keyEncipherment; and
 dataEncipherment.
 ************************************************/

@Lint(
        name = "e_rsa_allowed_ku_ee",
        description = "Key usage values digitalSignature, nonRepudiation, keyEncipherment, and dataEncipherment may only be present in an end entity certificate with an RSA key",
        citation = "RFC 3279: 2.3.1",
        source = Source.RFC3279,
        effectiveDate = EffectiveDate.RFC3279)
public class RsaAllowedKuEe implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());
        KeyUsage keyUsage = KeyUsage.getInstance(ASN1OctetString.getInstance(rawKeyUsage).getOctets());

        List<String> disallowedKUs = new ArrayList<>();

        checkKeyUsage(keyUsage, disallowedKUs, KeyUsage.keyAgreement, "keyAgreement");
        checkKeyUsage(keyUsage, disallowedKUs, KeyUsage.keyCertSign, "keyCertSign");
        checkKeyUsage(keyUsage, disallowedKUs, KeyUsage.cRLSign, "cRLSign");
        checkKeyUsage(keyUsage, disallowedKUs, KeyUsage.encipherOnly, "encipherOnly");
        checkKeyUsage(keyUsage, disallowedKUs, KeyUsage.decipherOnly, "decipherOnly");

        if (!disallowedKUs.isEmpty()) {
            return LintResult.of(Status.ERROR, String.format("Subscriber certificate with an RSA key contains invalid key usage(s): %s", String.join(", ", disallowedKUs)));
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasKeyUsageExtension(certificate) && Utils.isPublicKeyRSA(certificate) && Utils.isSubscriberCert(certificate);
    }

    private void checkKeyUsage(KeyUsage keyUsage, List<String> disallowedKUs, int disallowedKU, String dissalowedKUString) {
        if (keyUsage.hasUsages(disallowedKU)) {
            disallowedKUs.add(dissalowedKUString);
        }
    }
}
