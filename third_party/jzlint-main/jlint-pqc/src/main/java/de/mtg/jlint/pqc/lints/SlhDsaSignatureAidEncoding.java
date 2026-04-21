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
        name = "e_slh_dsa_signature_aid_encoding",
        description = "The algorithm identifier in the signature of a certificate signed by an SLH-DSA public key must have the correct encoding.",
        citation = "Section 3, Use of the SLH-DSA Signature Algorithm in the Cryptographic Message Syntax (CMS), https://www.ietf.org/archive/id/draft-ietf-lamps-cms-sphincs-plus-04.txt",
        source = Source.PQC,
        effectiveDate = EffectiveDate.ZERO)
public class SlhDsaSignatureAidEncoding implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        final List<String> acceptedSLHDSAsignatureAlgIDEncodings = Arrays.asList(
                "300b060960864801650304031a", //ID_ALG_SLH_DSA_128S_SHAKE
                "300b060960864801650304031b", //ID_ALG_SLH_DSA_128F_SHAKE
                "300b060960864801650304031c", //ID_ALG_SLH_DSA_128S_SHAKE
                "300b060960864801650304031d", //ID_ALG_SLH_DSA_192F_SHAKE
                "300b060960864801650304031e", //ID_ALG_SLH_DSA_256S_SHAKE
                "300b060960864801650304031f", //ID_ALG_SLH_DSA_256F_SHAKE
                "300b0609608648016503040314", //ID_ALG_SLH_DSA_128S_SHA2
                "300b0609608648016503040315", //ID_ALG_SLH_DSA_128F_SHA2
                "300b0609608648016503040316", //ID_ALG_SLH_DSA_192S_SHA2
                "300b0609608648016503040317", //ID_ALG_SLH_DSA_192F_SHA2
                "300b0609608648016503040318", //ID_ALG_SLH_DSA_256S_SHA2
                "300b0609608648016503040319"  //ID_ALG_SLH_DSA_256F_SHA2
        );

        try {
            ASN1Encodable signatureAlgorithmIdentifier = ASN1CertificateUtils.getInnerSignature(certificate);
            String hexEncoded = new String(Hex.encode(signatureAlgorithmIdentifier.toASN1Primitive().getEncoded(ASN1Encoding.DER)));
            if (acceptedSLHDSAsignatureAlgIDEncodings.contains(hexEncoded)) {
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
            return PQCUtils.isSignedBySLHDSA(certificate);
        } catch (CertificateEncodingException | IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
