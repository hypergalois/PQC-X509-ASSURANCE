package de.mtg.jzlint.lints.cabf_br;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.util.encoders.Hex;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.ASN1CertificateUtils;

/************************************************
 This lint refers to CAB Baseline
 Requirements (Version 1.7.4) chapter 7.1.3.1, which defines the
 required encodings of AlgorithmObjectIdentifiers inside a SubjectPublicKeyInfo field.
 Section 7.1.3.1.1: When encoded, the AlgorithmIdentifier for RSA keys MUST be byte-for-byte
 identical with the following hex-encoded bytes: 300d06092a864886f70d0101010500
 Section 7.1.3.1.2: When encoded, the AlgorithmIdentifier for ECDSA keys MUST be
 byte-for-byte identical with the following hex-encoded bytes:
 For P-256 keys: 301306072a8648ce3d020106082a8648ce3d030107
 For P-384 keys: 301006072a8648ce3d020106052b81040022
 For P-521 keys: 301006072a8648ce3d020106052b81040023
 ************************************************/

@Lint(
        name = "e_algorithm_identifier_improper_encoding",
        description = "Encoded AlgorithmObjectIdentifier objects inside a SubjectPublicKeyInfo field  MUST comply with specified byte sequences.",
        citation = "BRs: 7.1.3.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABFBRs_1_7_1_Date)
public class AlgorithmIdentifierImproperEncoding implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        final List<String> allowedPublicKeyEncodings = Arrays.asList(
                "300d06092a864886f70d0101010500",
                "301306072a8648ce3d020106082a8648ce3d030107",
                "301006072a8648ce3d020106052b81040022",
                "301006072a8648ce3d020106052b81040023");

        try {
            ASN1Sequence publicKeyAlgorithmIdentifier = ASN1CertificateUtils.getPublicKeyAlgorithmIdentifier(certificate);
            String hexEncoded = new String(Hex.encode(publicKeyAlgorithmIdentifier.getEncoded(ASN1Encoding.DER)));
            if (allowedPublicKeyEncodings.contains(hexEncoded)) {
                return LintResult.of(Status.PASS);
            }
            return LintResult.of(Status.ERROR, String.format("The encoded AlgorithmObjectIdentifier %s inside the SubjectPublicKeyInfo field is not allowed", hexEncoded));
        } catch (CertificateEncodingException | IOException ex) {
            return LintResult.of(Status.FATAL);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }

}
