package de.mtg.jlintissuer.lints.rfc;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.mtg.jlintissuer.JavaCRLIssuerLint;
import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;

@Lint(
        name = "e_crl_issuer_invalid_signature",
        description = "Check if the signature in the CRL validates correctly with the issuer's public key.",
        citation = "Sec. 5.1 RFC 5280",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.ZERO)
public class CRLIssuerLintInvalidSignature implements JavaCRLIssuerLint {

    @Override
    public LintResult execute(X509CRL crl, X509Certificate issuerCertificate) {
        try {
            crl.verify(issuerCertificate.getPublicKey(), new BouncyCastleProvider());
            return LintResult.of(Status.PASS);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | CRLException ex) {
            return LintResult.of(Status.ERROR);
        }
    }

    @Override
    public boolean checkApplies(X509CRL crl, X509Certificate issuerCertificate) {
        return true;
    }

}
