package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.ASN1CertificateUtils;

/************************************************
 RFC 5280: 4.1.2.2.  Serial Number
 The serial number MUST be a positive integer assigned by the CA to each
 certificate. It MUST be unique for each certificate issued by a given CA
 (i.e., the issuer name and serial number identify a unique certificate).
 CAs MUST force the serialNumber to be a non-negative integer.
 Given the uniqueness requirements above, serial numbers can be expected to
 contain long integers.  Certificate users MUST be able to handle serialNumber
 values up to 20 octets.  Conforming CAs MUST NOT use serialNumber values longer
 than 20 octets.
 Note: Non-conforming CAs may issue certificates with serial numbers that are
 negative or zero.  Certificate users SHOULD be prepared togracefully handle
 such certificates.
 ************************************************/

@Lint(
        name = "e_serial_number_longer_than_20_octets",
        description = "Certificates must not have a DER encoded serial number longer than 20 octets",
        citation = "RFC 5280: 4.1.2.2",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC3280)
public class SerialNumberLongerThan20Octets implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            ASN1Integer serialNumber = ASN1CertificateUtils.getSerialNumber(certificate);

            if (serialNumber.getEncoded(ASN1Encoding.DER).length > 22) {
                return LintResult.of(Status.ERROR);
            }
            return LintResult.of(Status.PASS);
        } catch (CertificateEncodingException | IOException ex) {
            return LintResult.of(Status.FATAL);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }
}
