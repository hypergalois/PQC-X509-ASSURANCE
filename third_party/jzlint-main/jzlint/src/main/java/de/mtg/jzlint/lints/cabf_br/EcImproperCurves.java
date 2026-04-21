package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.ASN1CertificateUtils;
import de.mtg.jzlint.utils.Utils;

/************************************************
 BRs: 6.1.5
 Certificates MUST meet the following requirements for algorithm type and key size.
 ECC Curve: NIST P-256, P-384, or P-521
 ************************************************/

@Lint(
        name = "e_ec_improper_curves",
        description = "Only one of NIST P-256, P-384, or P-521 can be used",
        citation = "BRs: 6.1.5",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        // Refer to BRs: 6.1.5, taking the statement "Before 31 Dec 2010" literally
        effectiveDate = EffectiveDate.ZERO)
public class EcImproperCurves implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {


        try {
            ASN1Sequence publicKeyAlgorithmIdentifier = ASN1CertificateUtils.getPublicKeyAlgorithmIdentifier(certificate);
            ASN1Encodable ecParameters = publicKeyAlgorithmIdentifier.getObjectAt(1);

            if (ecParameters instanceof ASN1ObjectIdentifier) {
                String oid = ((ASN1ObjectIdentifier) ecParameters).getId();

                if (oid.equals("1.2.840.10045.3.1.7") || oid.equals("1.3.132.0.34") || oid.equals("1.3.132.0.35")) {
                    return LintResult.of(Status.PASS);
                }
            }
        } catch (CertificateEncodingException ex) {
            return LintResult.of(Status.FATAL);
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isPublicKeyECC(certificate);
    }

}
