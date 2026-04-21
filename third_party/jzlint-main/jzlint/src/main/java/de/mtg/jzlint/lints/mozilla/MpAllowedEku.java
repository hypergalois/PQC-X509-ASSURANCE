package de.mtg.jzlint.lints.mozilla;

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

/********************************************************************
 Section 5.3 - Intermediate Certificates
 Intermediate certificates created after January 1, 2019, with the exception
 of cross-certificates that share a private key with a corresponding root
 certificate: MUST contain an EKU extension; and, MUST NOT include the
 anyExtendedKeyUsage KeyPurposeId; and, * MUST NOT include both the
 id-kp-serverAuth and id-kp-emailProtection KeyPurposeIds in the same
 certificate.
 Note that the lint cannot distinguish cross-certificates from other
 intermediates.
 ********************************************************************/

@Lint(
        name = "n_mp_allowed_eku",
        description = "A SubCA certificate must not have key usage that allows for both server auth and email protection, and must not use anyExtendedKeyUsage",
        citation = "Mozilla Root Store Policy / Section 5.3",
        source = Source.MOZILLA_ROOT_STORE_POLICY,
        effectiveDate = EffectiveDate.JANUARY_2019)
public class MpAllowedEku implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawEKU = certificate.getExtensionValue(Extension.extendedKeyUsage.getId());

        if (rawEKU == null) {
            return LintResult.of(Status.NOTICE, "Missing an EKU extension");
        }

        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(ASN1OctetString.getInstance(rawEKU).getOctets());

        if (extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.anyExtendedKeyUsage)) {
            return LintResult.of(Status.NOTICE, "SubCA has an anyExtendedKeyUsage in EKU extension");
        }

        if (extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_emailProtection) && extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth)) {
            return LintResult.of(Status.NOTICE, "SubCA has an id-kp-serverAuth and id-kp-emailProtection in EKU extension");
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubCA(certificate);
    }

}
