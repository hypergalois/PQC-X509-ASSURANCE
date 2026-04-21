package de.mtg.jlint.lints.cabf_br;

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
import java.time.ZoneId;
import java.time.ZonedDateTime;
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

import de.mtg.jlint.lints.CAExtension;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;

class SubjectOneAvaInstanceTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void passTest() throws Exception {
        {
            X500Name subjectDN = new X500Name("CN=Certificate, O=Lint, C=DE");
            X509Certificate certificate =
                    createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), subjectDN);
            caExtension.assertLintResult(LintResult.of(Status.PASS), new SubjectOneAvaInstance(), certificate);
        }
        {
            X500Name subjectDN = new X500Name("CN=Certificate, DC=example, DC=com, O=Lint, C=DE");
            X509Certificate certificate =
                    createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), subjectDN);
            caExtension.assertLintResult(LintResult.of(Status.PASS), new SubjectOneAvaInstance(), certificate);

        }
        {
            X500Name subjectDN = new X500Name("CN=Certificate, street=One, street=Two, O=Lint, C=DE");
            X509Certificate certificate =
                    createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), subjectDN);
            caExtension.assertLintResult(LintResult.of(Status.PASS), new SubjectOneAvaInstance(), certificate);
        }
    }

    @Test
    void errorTest() throws Exception {
        X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(),
                new X500Name("CN=First Appearance, O=Lint, CN=Second Appearance, C=DE"));
        caExtension.assertLintResult(LintResult.of(Status.ERROR), new SubjectOneAvaInstance(), certificate);
    }

    @Test
    void notApplicableTest() throws Exception {
        X509Certificate certificate = caExtension.getCaCertificate();
        caExtension.assertLintResult(LintResult.of(Status.NA), new SubjectOneAvaInstance(), certificate);
    }

    public X509Certificate createTestCertificate(PublicKey caPublicKey, PrivateKey caPrivateKey, X500Name caIssuerDN, X500Name subjectDN)
            throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, NoSuchProviderException,
            SignatureException, InvalidKeyException {

        BigInteger serialNumber = new BigInteger(96, new Random());
        ZonedDateTime notBefore = ZonedDateTime.of(2023, 9, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey);
        SubjectKeyIdentifier ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension skie = new Extension(Extension.subjectKeyIdentifier, false, ski.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(caIssuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN, subjectPublicKeyInfo);
        certificateBuilder.addExtension(akie);
        certificateBuilder.addExtension(skie);
        certificateBuilder.addExtension(CAExtension.getCertificatePolicies("2.23.140.1.5.1.2"));
        ContentSigner contentSigner =
                new JcaContentSignerBuilder(CAExtension.SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

    }

}
