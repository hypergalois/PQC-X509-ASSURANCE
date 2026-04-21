package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************************************
 RFC 5280: 4.2.1.9
 The cA boolean indicates whether the certified public key may be used
 to verify certificate signatures.  If the cA boolean is not asserted,
 then the keyCertSign bit in the key usage extension MUST NOT be
 asserted.  If the basic constraints extension is not present in a
 version 3 certificate, or the extension is present but the cA boolean
 is not asserted, then the certified public key MUST NOT be used to
 verify certificate signatures.
 ************************************************************************/

@Lint(
        name = "e_ext_key_usage_cert_sign_without_ca",
        description = "if the keyCertSign bit is asserted, then the cA bit in the basic constraints extension MUST also be asserted",
        citation = "RFC 5280: 4.2.1.3 & 4.2.1.9",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC3280)
public class ExtKeyUsageCertSignWithoutCa implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());

        KeyUsage keyUsage = KeyUsage.getInstance(ASN1OctetString.getInstance(rawKeyUsage).getOctets());

        if (!keyUsage.hasUsages(KeyUsage.keyCertSign)) {
            return LintResult.of(Status.PASS);
        }

        byte[] rawBasicConstraints = certificate.getExtensionValue(Extension.basicConstraints.getId());

        if (rawBasicConstraints == null) {
            return LintResult.of(Status.ERROR);
        }

        BasicConstraints basicConstraints = BasicConstraints.getInstance(ASN1OctetString.getInstance(rawBasicConstraints).getOctets());

        if (!basicConstraints.isCA()) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasKeyUsageExtension(certificate);
    }
}
