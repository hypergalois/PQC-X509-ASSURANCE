package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.ASN1CertificateUtils;

/*************************************************************************
 RFC 5280: 4.1.2.6
 Where it is non-empty, the subject field MUST contain an X.500
 distinguished name (DN). The DN MUST be unique for each subject
 entity certified by the one CA as defined by the issuer name field. A
 CA may issue more than one certificate with the same DN to the same
 subject entity.
 *************************************************************************/

@Lint(
        name = "e_subject_not_dn",
        description = "When not empty, the subject field MUST be a distinguished name",
        citation = "RFC 5280: 4.1.2.6",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class SubjectNotDn implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            ASN1Encodable subject = ASN1CertificateUtils.getSubject(certificate);

            byte[] encodedSubject;

            try {
                encodedSubject = subject.toASN1Primitive().getEncoded(ASN1Encoding.DER);
            } catch (IOException ex) {
                return LintResult.of(Status.FATAL);
            }

            try {
                X500Name.getInstance(encodedSubject);
            } catch (Exception ex) {
                return LintResult.of(Status.ERROR);
            }
        } catch (CertificateEncodingException ex) {
            return LintResult.of(Status.FATAL);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }
}
