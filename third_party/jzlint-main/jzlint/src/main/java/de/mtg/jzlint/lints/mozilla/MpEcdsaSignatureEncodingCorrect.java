package de.mtg.jzlint.lints.mozilla;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.util.encoders.Hex;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.ASN1CertificateUtils;


/************************************************
 https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/
 When a root or intermediate certificate's ECDSA key is used to produce a signature, only the following algorithms may
 be used, and with the following encoding requirements:
 If the signing key is P-256, the signature MUST use ECDSA with SHA-256. The encoded AlgorithmIdentifier MUST match the
 following hex-encoded bytes: 300a06082a8648ce3d040302.
 If the signing key is P-384, the signature MUST use ECDSA with SHA-384. The encoded AlgorithmIdentifier MUST match the
 following hex-encoded bytes: 300a06082a8648ce3d040303.
 The above encodings consist of the corresponding OID with the parameters field omitted, as specified by RFC 5758,
 Section 3.2. Certificates MUST NOT include a NULL parameter. Note this differs from RSASSA-PKCS1-v1_5, which includes
 an explicit NULL.
 ************************************************/

@Lint(
        name = "e_mp_ecdsa_signature_encoding_correct",
        description = "The encoded algorithm identifiers for ECDSA signatures MUST match specific hex-encoded bytes",
        citation = "Mozilla Root Store Policy / Section 5.1.2",
        source = Source.MOZILLA_ROOT_STORE_POLICY,
        effectiveDate = EffectiveDate.MozillaPolicy27Date)
public class MpEcdsaSignatureEncodingCorrect implements JavaLint {


    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] encodedSignatureAID;
        try {
            ASN1Encodable innerSignature = ASN1CertificateUtils.getInnerSignature(certificate);
            encodedSignatureAID = innerSignature.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        } catch (CertificateEncodingException | IOException ex) {
            return LintResult.of(Status.FATAL);
        }

        // see https://github.com/zmap/zlint/blob/master/v3/lints/mozilla/lint_mp_ecdsa_signature_encoding_correct.go
        // for the algorithm to calculate the result
        byte[] signature = certificate.getSignature();

        int maxP256SigByteLen = 72;
        int maxP384SigByteLen = 104;

        if (signature.length <= maxP256SigByteLen) {
            String expectedEncoding = "300a06082a8648ce3d040302";
            if (expectedEncoding.equals(new String(Hex.encode(encodedSignatureAID)))) {
                return LintResult.of(Status.PASS);
            }
            return LintResult.of(Status.ERROR, String.format("Encoding of signature algorithm does not match signing key on P-256 curve. Got the unsupported %s", new String(Hex.encode(encodedSignatureAID))));
        } else if (signature.length <= maxP384SigByteLen) {
            String expectedEncoding = "300a06082a8648ce3d040303";
            if (expectedEncoding.equals(new String(Hex.encode(encodedSignatureAID)))) {
                return LintResult.of(Status.PASS);
            }
            return LintResult.of(Status.ERROR, String.format("Encoding of signature algorithm does not match signing key on P-384 curve. Got the unsupported %s", new String(Hex.encode(encodedSignatureAID))));
        }
        return LintResult.of(Status.ERROR, String.format("Encoding of signature algorithm does not match signing key. Got signature length %d", signature.length));
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        final List<String> ecdsaAlgorithms = Arrays.asList(
                X9ObjectIdentifiers.ecdsa_with_SHA1.getId(),
                X9ObjectIdentifiers.ecdsa_with_SHA224.getId(),
                X9ObjectIdentifiers.ecdsa_with_SHA256.getId(),
                X9ObjectIdentifiers.ecdsa_with_SHA384.getId(),
                X9ObjectIdentifiers.ecdsa_with_SHA512.getId()
        );

        try {
            String innerSignatureOID = ASN1CertificateUtils.getInnerSignatureOID(certificate);
            return ecdsaAlgorithms.contains(innerSignatureOID);
        } catch (CertificateEncodingException ex) {
            throw new RuntimeException(ex);
        }
    }

}
