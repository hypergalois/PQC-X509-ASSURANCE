package de.mtg.jzlint.lints.rfc;

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
        name = "e_key_usage_incorrect_length",
        description = "The key usage is a bit string with exactly nine possible flags",
        citation = "RFC 5280: 4.2.1.3",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class KeyUsageIncorrectLength implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());
        byte[] rawValue = ASN1OctetString.getInstance(rawKeyUsage).getOctets();

        ASN1BitString asn1BitString = ASN1BitString.getInstance(rawValue);
        byte[] keyUsages = asn1BitString.getBytes();

        if (keyUsages.length == 1) {
            return LintResult.of(Status.PASS);
        }

        if (keyUsages.length > 2) {
            return LintResult.of(Status.ERROR);
        }

        if (Utils.getLowestSetBit(keyUsages[1]) != 8) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasKeyUsageExtension(certificate);
    }
}
