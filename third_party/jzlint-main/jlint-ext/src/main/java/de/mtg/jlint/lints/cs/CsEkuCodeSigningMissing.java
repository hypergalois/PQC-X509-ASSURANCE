package de.mtg.jlint.lints.cs;

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

/**
 * extKeyUsage
 * If the Certificate is a Code Signing Certificate, then id-kp-codeSigning MUST
 * be present and the following EKUs MAY be present:
 * • Lifetime Signing OID (1.3.6.1.4.1.311.10.3.13)
 * • id-kp-emailProtection
 * pg. 44
 * • Document Signing (1.3.6.1.4.1.311.3.10.3.12)
 * If the Certificate is a Timestamp Certificate, then id-kp-timeStamping MUST
 * be present and MUST be marked critical.
 * Additionally, the following EKUs MUST NOT be present:
 * • anyExtendedKeyUsage
 * • id-kp-serverAuth
 * Other values SHOULD NOT be present.
 */
@Lint(
        name = "e_cs_eku_code_signing_missing",
        description = "Check if the code signing certificate has the id-kp-codeSigning extended key usage.",
        citation = "Code Signing BR 7.1.2.3f",
        source = Source.CABF_CODE_SIGNING_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CS_BR_3_2_DATE)
public class CsEkuCodeSigningMissing implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawEKU = certificate.getExtensionValue(Extension.extendedKeyUsage.getId());
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(ASN1OctetString.getInstance(rawEKU).getOctets());
        if (extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_codeSigning)) {
            return LintResult.of(Status.PASS);
        }

        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return false;
    }

}