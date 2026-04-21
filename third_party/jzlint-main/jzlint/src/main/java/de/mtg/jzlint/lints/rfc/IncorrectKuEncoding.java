package de.mtg.jzlint.lints.rfc;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1BitString;
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
        name = "e_incorrect_ku_encoding",
        description = "RFC 5280 Section 4.2.1.3 describes the value of a KeyUsage to be a DER encoded BitString, which itself defines that all trailing 0 bits be counted as being \"unused\".",
        citation = "Where ITU-T Rec. X.680 | ISO/IEC 8824-1, 21.7, applies, the bitstring shall have all trailing 0 bits removed before it is encoded.",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.ZERO)
public class IncorrectKuEncoding implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());
        byte[] rawValue = ASN1OctetString.getInstance(rawKeyUsage).getOctets();

        if (rawValue.length < 4) {
            return LintResult.of(Status.ERROR, String.format("KeyUsage encodings must be at least four bytes long. Got %d bytes", rawValue.length));
        }

        ASN1BitString asn1BitString = ASN1BitString.getInstance(rawValue);
        int lowestSetBit = new BigInteger(1, asn1BitString.getBytes()).getLowestSetBit();

        if (asn1BitString.getPadBits() != lowestSetBit) {
            return LintResult.of(Status.ERROR, String.format("KeyUsage contains an inefficient encoding wherein the number of 'unused bits' is declared to be %d, but it should be %d", asn1BitString.getPadBits(), lowestSetBit));
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasKeyUsageExtension(certificate);
    }
}
