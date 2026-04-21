package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_key_usage_and_extended_key_usage_inconsistent",
        description = "The certificate MUST only be used for a purpose consistent with both key usage extension and extended key usage extension.",
        citation = "RFC 5280, Section 4.2.1.12.",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class KeyUsageAndExtendedKeyUsageInconsistent implements JavaLint {

    // KU combinations with Server Authentication EKU:
    //  RFC 5280 4.2.1.12 on KU consistency with Server Authentication EKU:
    //    -- TLS WWW server authentication
    //    -- Key usage bits that may be consistent: digitalSignature,
    //    -- keyEncipherment or keyAgreement

    // (digitalSignature OR (keyEncipherment XOR keyAgreement))
    private static final List<Integer> CONSISTENT_SERVER_AUTH = Arrays.asList(
            KeyUsage.digitalSignature,
            KeyUsage.keyEncipherment,
            KeyUsage.keyAgreement,
            KeyUsage.digitalSignature | KeyUsage.keyEncipherment,
            KeyUsage.digitalSignature | KeyUsage.keyAgreement);

    // KU combinations with Client Authentication EKU:
    //  RFC 5280 4.2.1.12 on KU consistency with Client Authentication EKU:
    //    -- TLS WWW client authentication
    //    -- Key usage bits that may be consistent: digitalSignature
    //    -- and/or keyAgreement

    // (digitalSignature OR keyAgreement)
    private static final List<Integer> CONSISTENT_CLIENT_AUTH = Arrays.asList(
            KeyUsage.digitalSignature,
            KeyUsage.keyAgreement,
            KeyUsage.digitalSignature | KeyUsage.keyAgreement);

    // KU combinations with Code Signing EKU:
    //  RFC 5280 4.2.1.12 on KU consistency with Code Signing EKU:
    //   -- Signing of downloadable executable code
    //   -- Key usage bits that may be consistent: digitalSignature

    // (digitalSignature)
    private static final List<Integer> CONSISTENT_CODE_SIGNING = Arrays.asList(KeyUsage.digitalSignature);

    // KU combinations with Email Protection EKU:
    //  RFC 5280 4.2.1.12 on KU consistency with Email Protection EKU:
    //    -- Email protection
    //    -- Key usage bits that may be consistent: digitalSignature,
    //    -- nonRepudiation, and/or (keyEncipherment or keyAgreement)
    //  Note: Recent editions of X.509 have renamed nonRepudiation bit to contentCommitment

    // (digitalSignature OR nonRepudiation OR (keyEncipherment XOR keyAgreement))
    private static final List<Integer> CONSISTENT_EMAIL_PROTECTION = Arrays.asList(
            KeyUsage.digitalSignature,
            KeyUsage.nonRepudiation,
            KeyUsage.keyEncipherment,
            KeyUsage.keyAgreement,
            KeyUsage.digitalSignature | KeyUsage.nonRepudiation,
            KeyUsage.digitalSignature | KeyUsage.keyEncipherment,
            KeyUsage.digitalSignature | KeyUsage.keyAgreement,
            KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyEncipherment,
            KeyUsage.digitalSignature | KeyUsage.nonRepudiation | KeyUsage.keyAgreement,
            KeyUsage.nonRepudiation | KeyUsage.keyEncipherment,
            KeyUsage.nonRepudiation | KeyUsage.keyAgreement);


    // KU combinations with Time Stamping EKU:
    //  RFC 5280 4.2.1.12 on KU consistency with Time Stamping EKU:
    //    -- Binding the hash of an object to a time
    //    -- Key usage bits that may be consistent: digitalSignature
    //    -- and/or nonRepudiation
    //  Note: Recent editions of X.509 have renamed nonRepudiation bit to contentCommitment

    // (digitalSignature OR nonRepudiation)
    private static final List<Integer> CONSISTENT_TIME_STAMPING = Arrays.asList(
            KeyUsage.digitalSignature,
            KeyUsage.nonRepudiation,
            KeyUsage.digitalSignature | KeyUsage.nonRepudiation);

    // KU combinations with Ocsp Signing EKU:
    //  RFC 5280 4.2.1.12 on KU consistency with Ocsp Signing EKU:
    //    -- Signing OCSP responses
    //    -- Key usage bits that may be consistent: digitalSignature
    //    -- and/or nonRepudiation
    //  Note: Recent editions of X.509 have renamed nonRepudiation bit to contentCommitment

    // (digitalSignature OR nonRepudiation)
    private static final List<Integer> CONSISTENT_OCSP = Arrays.asList(
            KeyUsage.digitalSignature,
            KeyUsage.nonRepudiation,
            KeyUsage.digitalSignature | KeyUsage.nonRepudiation);

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawEKU = certificate.getExtensionValue(Extension.extendedKeyUsage.getId());
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(ASN1OctetString.getInstance(rawEKU).getOctets());
        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());
        byte[] rawValue = ASN1OctetString.getInstance(rawKeyUsage).getOctets();
        ASN1BitString asn1BitString = ASN1BitString.getInstance(rawValue);
        int rawKeyUsageValue = asn1BitString.intValue();

        KeyPurposeId[] usages = extendedKeyUsage.getUsages();

        for (KeyPurposeId keyPurposeId : usages) {
            if (KeyPurposeId.id_kp_serverAuth.toOID().equals(keyPurposeId.toOID())) {
                if (CONSISTENT_SERVER_AUTH.contains(rawKeyUsageValue)) {
                    return LintResult.of(Status.PASS);
                }
            }
            if (KeyPurposeId.id_kp_clientAuth.toOID().equals(keyPurposeId.toOID())) {
                if (CONSISTENT_CLIENT_AUTH.contains(rawKeyUsageValue)) {
                    return LintResult.of(Status.PASS);
                }
            }
            if (KeyPurposeId.id_kp_codeSigning.toOID().equals(keyPurposeId.toOID())) {
                if (CONSISTENT_CODE_SIGNING.contains(rawKeyUsageValue)) {
                    return LintResult.of(Status.PASS);
                }
            }
            if (KeyPurposeId.id_kp_emailProtection.toOID().equals(keyPurposeId.toOID())) {
                if (CONSISTENT_EMAIL_PROTECTION.contains(rawKeyUsageValue)) {
                    return LintResult.of(Status.PASS);
                }
            }
            if (KeyPurposeId.id_kp_timeStamping.toOID().equals(keyPurposeId.toOID())) {
                if (CONSISTENT_TIME_STAMPING.contains(rawKeyUsageValue)) {
                    return LintResult.of(Status.PASS);
                }
            }
            if (KeyPurposeId.id_kp_OCSPSigning.toOID().equals(keyPurposeId.toOID())) {
                if (CONSISTENT_OCSP.contains(rawKeyUsageValue)) {
                    return LintResult.of(Status.PASS);
                }
            }
            return LintResult.of(Status.ERROR, "KeyUsage inconsistent with ExtKeyUsage");
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) &&
                Utils.hasExtendedKeyUsageExtension(certificate) &&
                Utils.hasKeyUsageExtension(certificate);
    }

}
