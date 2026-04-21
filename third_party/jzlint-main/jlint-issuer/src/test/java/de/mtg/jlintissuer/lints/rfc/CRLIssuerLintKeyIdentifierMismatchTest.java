package de.mtg.jlintissuer.lints.rfc;

import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
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

class CRLIssuerLintKeyIdentifierMismatchTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void passTest() throws NoSuchAlgorithmException, IOException, OperatorCreationException, CRLException {
        X509CRL crl = caExtension.createCRL();
        X509Certificate caCertificate = caExtension.getCaCertificate();
        caExtension.assertCRLIssuerLintResult(LintResult.of(Status.PASS), true, new CRLIssuerLintKeyIdentifierMismatch(), crl, caCertificate);
    }

    @Test
    void errorTest() throws NoSuchAlgorithmException, IOException, NoSuchProviderException, CertificateException, OperatorCreationException, CRLException {
        X509Certificate caCertificate = caExtension.getCaCertificate();
        X509CRL crl = createWrongCRL(caExtension.getIsserDN(), caExtension.getCaPrivateKey());
        caExtension.assertCRLIssuerLintResult(LintResult.of(Status.ERROR), true, new CRLIssuerLintKeyIdentifierMismatch(), crl, caCertificate);
    }

    @Test
    void naTest() throws OperatorCreationException, CRLException {
        X509Certificate caCertificate = caExtension.getCaCertificate();
        X509CRL crl = createAbsentAKICRL(caExtension.getIsserDN(), caExtension.getCaPrivateKey());
        caExtension.assertCRLIssuerLintResult(LintResult.of(Status.NA), false, new CRLIssuerLintKeyIdentifierMismatch(), crl, caCertificate);
    }

    private X509CRL createWrongCRL(X500Name caIssuerDN, PrivateKey caPrivateKey) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, NoSuchProviderException, CRLException {

        Date thisUpdate = Date.from(LocalDateTime.now().minusHours(1).atZone(ZoneId.systemDefault()).toInstant());
        Date nextUpdate = Date.from(LocalDateTime.now().plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        PublicKey randomPublicKey = keyPairGenerator.generateKeyPair().getPublic();

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(randomPublicKey);
        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension crlNumber = new Extension(Extension.cRLNumber, false, new ASN1Integer(1).getEncoded(ASN1Encoding.DER));

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(caIssuerDN, thisUpdate);
        crlBuilder.setNextUpdate(nextUpdate);
        crlBuilder.addExtension(akie);
        crlBuilder.addExtension(crlNumber);
        ContentSigner contentSigner = new JcaContentSignerBuilder(CAExtension.SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CRLHolder holder = crlBuilder.build(contentSigner);

        return new JcaX509CRLConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCRL(holder);

    }

    private X509CRL createAbsentAKICRL(X500Name caIssuerDN, PrivateKey caPrivateKey) throws OperatorCreationException, CRLException {

        Date thisUpdate = Date.from(LocalDateTime.now().minusHours(1).atZone(ZoneId.systemDefault()).toInstant());
        Date nextUpdate = Date.from(LocalDateTime.now().plusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(caIssuerDN, thisUpdate);
        crlBuilder.setNextUpdate(nextUpdate);
        ContentSigner contentSigner = new JcaContentSignerBuilder(CAExtension.SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CRLHolder holder = crlBuilder.build(contentSigner);
        return new JcaX509CRLConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCRL(holder);

    }

}
