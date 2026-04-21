package de.mtg.jzlint.lints.mozilla;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
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
 Section 5.1.1 RSA
 RSASSA-PSS with SHA-256, MGF-1 with SHA-256, and a salt length of 32 bytes.
 The encoded AlgorithmIdentifier MUST match the following hex-encoded bytes:
 304106092a864886f70d01010a3034a00f300d0609608648016503040201
 0500a11c301a06092a864886f70d010108300d0609608648016503040201
 0500a203020120
 RSASSA-PSS with SHA-384, MGF-1 with SHA-384, and a salt length of 48 bytes.
 The encoded AlgorithmIdentifier MUST match the following hex-encoded bytes:
 304106092a864886f70d01010a3034a00f300d0609608648016503040202
 0500a11c301a06092a864886f70d010108300d0609608648016503040202
 0500a203020130
 RSASSA-PSS with SHA-512, MGF-1 with SHA-512, and a salt length of 64 bytes.
 The encoded AlgorithmIdentifier MUST match the following hex-encoded bytes:
 304106092a864886f70d01010a3034a00f300d0609608648016503040203
 0500a11c301a06092a864886f70d010108300d0609608648016503040203
 0500a203020140
 ************************************************/

@Lint(
        name = "e_mp_rsassa-pss_parameters_encoding_in_signature_algorithm_correct",
        description = "The encoded AlgorithmIdentifier for RSASSA-PSS in the signature algorithm MUST match specific bytes",
        citation = "Mozilla Root Store Policy / Section 5.1.1",
        source = Source.MOZILLA_ROOT_STORE_POLICY,
        effectiveDate = EffectiveDate.MozillaPolicy27Date)
public class PssParametersEncodingInSignatureAlgorithmCorrect implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        final List<String> acceptedPSSAlgIDEncodings = Arrays.asList(
                // RSASSA-PSS with SHA-256, MGF-1 with SHA-256, salt length 32 bytes
                "304106092a864886f70d01010a3034a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402010500a203020120",
                // RSASSA-PSS with SHA-384, MGF-1 with SHA-384, salt length 48 bytes
                "304106092a864886f70d01010a3034a00f300d06096086480165030402020500a11c301a06092a864886f70d010108300d06096086480165030402020500a203020130",
                // RSASSA-PSS with SHA-512, MGF-1 with SHA-512, salt length 64 bytes
                "304106092a864886f70d01010a3034a00f300d06096086480165030402030500a11c301a06092a864886f70d010108300d06096086480165030402030500a203020140");

        byte[] encodedSignatureAID;
        try {
            ASN1Encodable innerSignature = ASN1CertificateUtils.getInnerSignature(certificate);
            encodedSignatureAID = innerSignature.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        } catch (CertificateEncodingException | IOException ex) {
            return LintResult.of(Status.FATAL);
        }

        if (acceptedPSSAlgIDEncodings.contains(new String(Hex.encode(encodedSignatureAID)))) {
            return LintResult.of(Status.PASS);
        }

        return LintResult.of(Status.ERROR, String.format("RSASSA-PSS parameters are not properly encoded. %d presentations are allowed but got the unsupported %s", acceptedPSSAlgIDEncodings.size(), new String(Hex.encode(encodedSignatureAID))));
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        try {
            return PKCSObjectIdentifiers.id_RSASSA_PSS.getId().equals(ASN1CertificateUtils.getInnerSignatureOID(certificate));
        } catch (CertificateEncodingException ex) {
            throw new RuntimeException(ex);
        }

    }

}
