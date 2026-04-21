package de.mtg.jzlint.lints.rfc;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Null;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.ASN1CertificateUtils;

/*******************************************************************************************************
 "RFC5280: RFC 4055, Section 1.2"
 RSA: Encoded algorithm identifier MUST have NULL parameters.
 *******************************************************************************************************/
@Lint(
        name = "e_spki_rsa_encryption_parameter_not_null",
        description = "RSA: Encoded public key algorithm identifier MUST have NULL parameters",
        citation = "RFC 4055, Section 1.2",
        source = Source.RFC5280, // RFC4055 is referenced in lint.RFC5280, Section 1
        effectiveDate = EffectiveDate.RFC5280)
public class SpkiRsaEncryptionParameterNotNull implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {

            Optional<ASN1Encodable> publicKeyParameters = ASN1CertificateUtils.getPublicKeyParameters(certificate);

            if (!publicKeyParameters.isPresent()) {
                return LintResult.of(Status.ERROR);
            }

            if (!(publicKeyParameters.get() instanceof ASN1Null)) {
                return LintResult.of(Status.ERROR);
            }
            return LintResult.of(Status.PASS);
        } catch (CertificateEncodingException ex) {
            return LintResult.of(Status.FATAL);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded());
        return PKCSObjectIdentifiers.rsaEncryption.getId().equals(subjectPublicKeyInfo.getAlgorithm().getAlgorithm().getId());
    }
}
