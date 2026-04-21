package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 RFC 5280: 4.2.1.12
 If a CA includes extended key usages to satisfy such applications,
 but does not wish to restrict usages of the key, the CA can include
 the special KeyPurposeId anyExtendedKeyUsage in addition to the
 particular key purposes required by the applications.  Conforming CAs
 SHOULD NOT mark this extension as critical if the anyExtendedKeyUsage
 KeyPurposeId is present.  Applications that require the presence of a
 particular purpose MAY reject certificates that include the
 anyExtendedKeyUsage OID but not the particular OID expected for the
 application.
 ************************************************/
@Lint(
        name = "w_eku_critical_improperly",
        description = "Conforming CAs SHOULD NOT mark extended key usage extension as critical if the anyExtendedKeyUsage KeyPurposedID is present",
        citation = "RFC 5280: 4.2.1.12",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC3280)
public class EkuCriticalImproperly implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.isExtendedKeyUsageExtensionCritical(certificate)) {
            byte[] rawEKU = certificate.getExtensionValue(Extension.extendedKeyUsage.getId());
            ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(ASN1OctetString.getInstance(rawEKU).getOctets());
            if (extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.anyExtendedKeyUsage)) {
                return LintResult.of(Status.WARN);
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtendedKeyUsageExtension(certificate);
    }
}
