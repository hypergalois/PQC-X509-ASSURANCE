package de.mtg.jlintissuer.lints.rfc;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.mtg.jlintissuer.JavaIssuerLint;
import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

@Lint(
        name = "e_issuer_invalid_signature",
        description = "Check if the signature in the certificate validates correctly with the issuer's public key.",
        citation = "Sec. 4.1.1.3 RFC 5280",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.ZERO)
public class IssuerLintInvalidSignature implements JavaIssuerLint {

    @Override
    public LintResult execute(X509Certificate certificate, X509Certificate issuerCertificate) {
        try {
            certificate.verify(issuerCertificate.getPublicKey(), new BouncyCastleProvider());
            return LintResult.of(Status.PASS);
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
            return LintResult.of(Status.ERROR);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate, X509Certificate issuerCertificate) {
        return true;
    }


}
