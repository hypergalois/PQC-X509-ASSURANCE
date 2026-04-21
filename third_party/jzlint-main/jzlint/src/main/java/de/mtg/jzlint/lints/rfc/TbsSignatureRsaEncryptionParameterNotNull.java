package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.ASN1Sequence;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.ASN1CertificateUtils;
import de.mtg.jzlint.utils.Utils;


@Lint(
        name = "e_tbs_signature_rsa_encryption_parameter_not_null",
        description = "RSA: Encoded signature algorithm identifier MUST have NULL parameters",
        citation = "RFC 4055, Section 5",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class TbsSignatureRsaEncryptionParameterNotNull implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {

            ASN1Encodable innerSignature = ASN1CertificateUtils.getInnerSignature(certificate);

            ASN1Sequence algorithmIdentifier = ASN1Sequence.getInstance(innerSignature.toASN1Primitive().getEncoded(ASN1Encoding.DER));

            if (algorithmIdentifier.size() == 1) {
                return LintResult.of(Status.ERROR);
            }

            ASN1Encodable params = algorithmIdentifier.getObjectAt(1);

            if (!(params instanceof ASN1Null)) {
                return LintResult.of(Status.ERROR);
            }
            return LintResult.of(Status.PASS);
        } catch (CertificateEncodingException | IOException ex) {
            return LintResult.of(Status.FATAL);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasRSASignatureOID(certificate);
    }

}
