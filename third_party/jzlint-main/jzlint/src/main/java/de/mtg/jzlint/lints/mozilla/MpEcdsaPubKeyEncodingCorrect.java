package de.mtg.jzlint.lints.mozilla;

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
import de.mtg.jzlint.utils.Utils;

/************************************************
 https://www.mozilla.org/en-US/about/governance/policies/security-group/certs/policy/
 When ECDSA keys are encoded in a SubjectPublicKeyInfo structure, the algorithm field MUST be one of the following, as
 specified by RFC 5480, Section 2.1.1:
 The encoded AlgorithmIdentifier for a P-256 key MUST match the following hex-encoded
 bytes: > 301306072a8648ce3d020106082a8648ce3d030107.
 The encoded AlgorithmIdentifier for a P-384 key MUST match the following hex-encoded
 bytes: > 301006072a8648ce3d020106052b81040022.
 The above encodings consist of an ecPublicKey OID (1.2.840.10045.2.1) with a named curve parameter of the corresponding
 curve OID. Certificates MUST NOT use the implicit or specified curve forms.
 ************************************************/

@Lint(
        name = "e_mp_ecdsa_pub_key_encoding_correct",
        description = "The encoded algorithm identifiers for ECDSA public keys MUST match specific bytes",
        citation = "Mozilla Root Store Policy / Section 5.1.2",
        source = Source.MOZILLA_ROOT_STORE_POLICY,
        effectiveDate = EffectiveDate.MozillaPolicy27Date)
public class MpEcdsaPubKeyEncodingCorrect implements JavaLint {


    @Override
    public LintResult execute(X509Certificate certificate) {

        final List<String> acceptedECPublicKeyAlgIDEncodings = Arrays.asList(
                // encoded AlgorithmIdentifier for a P-256 key
                "301306072a8648ce3d020106082a8648ce3d030107",
                // encoded AlgorithmIdentifier for a P-384 key
                "301006072a8648ce3d020106052b81040022");

        try {
            ASN1Sequence publicKeyAlgorithmIdentifier = ASN1CertificateUtils.getPublicKeyAlgorithmIdentifier(certificate);
            String hexEncoded = new String(Hex.encode(publicKeyAlgorithmIdentifier.getEncoded(ASN1Encoding.DER)));
            if (acceptedECPublicKeyAlgIDEncodings.contains(hexEncoded)) {
                return LintResult.of(Status.PASS);
            }
            return LintResult.of(Status.ERROR, String.format("Wrong encoding of ECC public key. Got the unsupported %s", hexEncoded));
        } catch (CertificateEncodingException | IOException ex) {
            return LintResult.of(Status.FATAL);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isPublicKeyECC(certificate);
    }

}
