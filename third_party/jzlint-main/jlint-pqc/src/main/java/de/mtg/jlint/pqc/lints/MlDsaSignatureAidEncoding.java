package de.mtg.jlint.pqc.lints;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.util.encoders.Hex;

import de.mtg.jlint.pqc.util.PQCUtils;
import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.ASN1CertificateUtils;

@Lint(
        name = "e_ml_dsa_signature_aid_encoding",
        description = "The algorithm identifier in the signature of a certificate signed by an ML-DSA public key must have the correct encoding.",
        citation = "Internet X.509 Public Key Infrastructure: Algorithm Identifiers for ML-DSA, https://www.ietf.org/archive/id/draft-ietf-lamps-dilithium-certificates-04.txt",
        source = Source.PQC,
        effectiveDate = EffectiveDate.ZERO)
public class MlDsaSignatureAidEncoding implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        final List<String> acceptedMLDSASignatureAlgIDEncodings = Arrays.asList(
                "300b0609608648016503040311", //ID_ML_DSA_44
                "300b0609608648016503040312", //ID_ML_DSA_65
                "300b0609608648016503040313" //ID_ML_DSA_87
        );

        try {
            ASN1Encodable signatureAlgorithmIdentifier = ASN1CertificateUtils.getInnerSignature(certificate);
            String hexEncoded = new String(Hex.encode(signatureAlgorithmIdentifier.toASN1Primitive().getEncoded(ASN1Encoding.DER)));
            if (acceptedMLDSASignatureAlgIDEncodings.contains(hexEncoded)) {
                return LintResult.of(Status.PASS);
            }
            return LintResult.of(Status.ERROR, String.format("Wrong encoding of ML-DSA signature. Got the unsupported %s", hexEncoded));
        } catch (CertificateEncodingException | IOException ex) {
            return LintResult.of(Status.FATAL);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        try {
            return PQCUtils.isSignedByMLDSA(certificate);
        } catch (CertificateEncodingException | IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
