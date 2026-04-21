package de.mtg.jlintissuer.lints.rfc;

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.util.encoders.Hex;

import de.mtg.jlintissuer.JavaIssuerLint;
import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_issuer_lint_key_identifier_mismatch",
        description = "Check if the key identifier in the AKI extension of the certificate matches the key identifier calculated from the public key of the issuer.",
        citation = "Sec. 4.2.1.1 RFC 5280",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.ZERO)
public class IssuerLintKeyIdentifierMismatch implements JavaIssuerLint {

    @Override
    public LintResult execute(X509Certificate certificate, X509Certificate issuerCertificate) {

        byte[] keyIdentifier = getAKIKeyIdentifier(certificate).get();
        JcaX509ExtensionUtils utils;

        try {
            utils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }

        SubjectKeyIdentifier truncatedSKI = utils.createTruncatedSubjectKeyIdentifier(issuerCertificate.getPublicKey());
        byte[] truncatedIssuerKeyIdentifier = truncatedSKI.getKeyIdentifier();

        if (Arrays.equals(truncatedIssuerKeyIdentifier, keyIdentifier)) {
            return LintResult.of(Status.PASS);
        }

        SubjectKeyIdentifier ski = utils.createSubjectKeyIdentifier(issuerCertificate.getPublicKey());
        byte[] issuerKeyIdentifier = ski.getKeyIdentifier();

        if (Arrays.equals(issuerKeyIdentifier, keyIdentifier)) {
            return LintResult.of(Status.PASS);
        }

        return LintResult.of(Status.ERROR, String.format("Certificate has AKI key identifier %s while issuer's public key has %s or %s in truncated form.", new String(Hex.encode(keyIdentifier)), new String(Hex.encode(issuerKeyIdentifier)), new String(Hex.encode(truncatedIssuerKeyIdentifier))));
    }

    @Override
    public boolean checkApplies(X509Certificate certificate, X509Certificate issuerCertificate) {
        return getAKIKeyIdentifier(certificate).isPresent();
    }

    private static Optional<byte[]> getAKIKeyIdentifier(X509Certificate certificate) {
        if (!Utils.hasExtension(certificate, Extension.authorityKeyIdentifier.getId())) {
            return Optional.empty();
        }
        byte[] rawAKI = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(rawAKI).getOctets());
        return Optional.ofNullable(authorityKeyIdentifier.getKeyIdentifier());
    }

}
