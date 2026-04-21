package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

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


/*******************************************************************************************************
 BRs: 7.1.2.3
 extKeyUsage (required)
 Either the value id-kp-serverAuth [RFC5280] or id-kp-clientAuth [RFC5280] or
 both values MUST be present. id-kp-emailProtection [RFC5280] MAY be present.
 Other values SHOULD NOT be present. The value anyExtendedKeyUsage MUST NOT be
 present.
 *******************************************************************************************************/

@Lint(
        name = "w_sub_cert_eku_extra_values",
        description = "Subscriber Certificate: extKeyUsage values other than id-kp-serverAuth, id-kp-clientAuth, and id-kp-emailProtection SHOULD NOT be present.",
        citation = "BRs: 7.1.2.3",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class SubCertEkuExtraValues implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawExtendedKeyUsage = certificate.getExtensionValue(Extension.extendedKeyUsage.getId());
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(ASN1OctetString.getInstance(rawExtendedKeyUsage).getOctets());

        List<String> allowedUsages = Arrays.asList(KeyPurposeId.id_kp_serverAuth.getId(),
                KeyPurposeId.id_kp_clientAuth.getId(),
                KeyPurposeId.id_kp_emailProtection.getId());

        KeyPurposeId[] usages = extendedKeyUsage.getUsages();

        for (KeyPurposeId keyPurposeId : usages) {
            if (!allowedUsages.contains(keyPurposeId.getId())) {
                return LintResult.of(Status.WARN);
            }
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) && Utils.hasExtendedKeyUsageExtension(certificate);
    }

}
