package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;


@Lint(
        name = "e_superfluous_ku_encoding",
        description = "RFC 5280 Section 4.2.1.3 describes the value of a KeyUsage to be a DER encoded BitString, which itself must not have unnecessary trailing 00 bytes.",
        citation = "1.2.2 Where Rec. ITU-T X.680 | ISO/IEC 8824-1, 22.7, applies, the bitstring shall have all trailing 0 bits removed before it is encoded.",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.ZERO)
public class SuperfluousKuEncoding implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());
        byte[] rawValue = ASN1OctetString.getInstance(rawKeyUsage).getOctets();

        if (rawValue[rawValue.length - 1] != 0) {
            return LintResult.of(Status.PASS);
        }

        return LintResult.of(Status.ERROR, String.format("KeyUsage contains superfluous trailing 00 byte."));

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasKeyUsageExtension(certificate);
    }
}
