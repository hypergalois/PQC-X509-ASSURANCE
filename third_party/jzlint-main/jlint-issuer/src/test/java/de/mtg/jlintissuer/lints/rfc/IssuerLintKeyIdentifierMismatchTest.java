package de.mtg.jlintissuer.lints.rfc;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlintissuer.CAExtension;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;

class IssuerLintKeyIdentifierMismatchTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void passTest() throws CertificateException, NoSuchAlgorithmException, IOException, SignatureException, OperatorCreationException, NoSuchProviderException, InvalidKeyException {
        X509Certificate caCertificate = caExtension.getCaCertificate();
        X509Certificate issuedCertificate = caExtension.createEECertificate();
        caExtension.assertLintResult(LintResult.of(Status.PASS), true, new IssuerLintKeyIdentifierMismatch(), issuedCertificate, caCertificate);
    }

    @Test
    void errorTest() throws NoSuchAlgorithmException, IOException, NoSuchProviderException, CertificateException, OperatorCreationException {
        X509Certificate caCertificate = caExtension.getCaCertificate();
        X509Certificate issuedCertificate = createWrongCertificate(caExtension.getIsserDN(), caExtension.getCaPrivateKey());
        caExtension.assertLintResult(LintResult.of(Status.ERROR), true, new IssuerLintKeyIdentifierMismatch(), issuedCertificate, caCertificate);
    }

    private X509Certificate createWrongCertificate(X500Name issuerDN, PrivateKey issuerKey) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, NoSuchProviderException {

        BigInteger serialNumber = new BigInteger(96, new Random());
        Date notBefore = Date.from(LocalDateTime.now().minusHours(1).atZone(ZoneId.systemDefault()).toInstant());
        Date noteAfter = Date.from(LocalDateTime.now().plusYears(1).atZone(ZoneId.systemDefault()).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        X500Name subjectDN = new X500Name("CN=Certificate, O=Lint, C=DE");

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(publicKey); // use own key
        SubjectKeyIdentifier ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension skie = new Extension(Extension.subjectKeyIdentifier, false, ski.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(issuerDN, serialNumber, notBefore, noteAfter, subjectDN, subjectPublicKeyInfo);
        certificateBuilder.addExtension(akie);
        certificateBuilder.addExtension(skie);
        ContentSigner contentSigner = new JcaContentSignerBuilder(CAExtension.SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(issuerKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

    }

}
