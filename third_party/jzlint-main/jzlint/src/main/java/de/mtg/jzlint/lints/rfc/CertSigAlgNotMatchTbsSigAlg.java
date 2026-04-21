package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Encoding;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.ASN1CertificateUtils;

/*******************************************************************
 RFC 5280: 4.1.1.2
 [the Certificate signatureAlgorithm] field MUST contain the same
 algorithm identifier as the signature field in the sequence
 tbsCertificate
 ********************************************************************/

@Lint(
        name = "e_cert_sig_alg_not_match_tbs_sig_alg",
        description = "Certificate signature field must match TBSCertificate signature field",
        citation = "RFC 5280, Section 4.1.1.2",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class CertSigAlgNotMatchTbsSigAlg implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            byte[] encodedInnerSignature = ASN1CertificateUtils.getInnerSignature(certificate).toASN1Primitive().getEncoded(ASN1Encoding.DER);
            byte[] encodedOuterSignature = ASN1CertificateUtils.getOuterSignature(certificate).toASN1Primitive().getEncoded(ASN1Encoding.DER);
            if (!Arrays.equals(encodedInnerSignature, encodedOuterSignature)) {
                return LintResult.of(Status.ERROR);
            }
            return LintResult.of(Status.PASS);
        } catch (IOException | CertificateEncodingException ex) {
            return LintResult.of(Status.FATAL);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }
}
