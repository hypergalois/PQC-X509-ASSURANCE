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

/***********************************************************************
 This profile does not restrict the combinations of bits that may be
 set in an instantiation of the keyUsage extension.  However,
 appropriate values for keyUsage extensions for particular algorithms
 are specified in [RFC3279], [RFC4055], and [RFC4491].  When the
 keyUsage extension appears in a certificate, at least one of the bits
 MUST be set to 1.
 ***********************************************************************/

@Lint(
        name = "e_ext_key_usage_without_bits",
        description = "When the keyUsage extension is included, at least one bit MUST be set to 1",
        citation = "RFC 5280: 4.2.1.3",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class ExtKeyUsageWithoutBits implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());

        ASN1BitString keyUsageValue = ASN1BitString.getInstance(ASN1OctetString.getInstance(rawKeyUsage).getOctets());

        if (keyUsageValue.intValue() == 0) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasKeyUsageExtension(certificate);
    }
}
