package de.mtg.jzlint.lints.community;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

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
        name = "e_rsa_no_public_key",
        description = "The RSA public key should be present",
        citation = "awslabs certlint",
        source = Source.COMMUNITY,
        effectiveDate = EffectiveDate.ZERO)
public class RsaNoPublicKey implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            ASN1Sequence publicKey = ASN1CertificateUtils.getPublicKey(certificate);
            if (publicKey.size() == 1 || publicKey.getObjectAt(1) == null) {
                return LintResult.of(Status.ERROR);
            }
        } catch (CertificateEncodingException ex) {
            return LintResult.of(Status.FATAL);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isPublicKeyRSA(certificate);
    }

}
