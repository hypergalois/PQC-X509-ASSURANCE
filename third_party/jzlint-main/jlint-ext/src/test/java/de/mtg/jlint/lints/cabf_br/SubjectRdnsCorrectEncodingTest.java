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
import java.security.spec.AlgorithmParameterSpec;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlint.lints.CAExtension;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;

class SubjectRdnsCorrectEncodingTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void passTest() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        {
            List<RDN> rdns = new ArrayList<>();

            rdns.add(new RDN(BCStyle.CN, new DERUTF8String("UTF8")));
            rdns.add(new RDN(BCStyle.OU, new DERUTF8String("UTF8")));
            rdns.add(new RDN(BCStyle.GIVENNAME, new DERUTF8String("UTF8")));
            rdns.add(new RDN(BCStyle.SURNAME, new DERUTF8String("UTF8")));
            rdns.add(new RDN(BCStyle.O, new DERUTF8String("UTF8")));
            rdns.add(new RDN(BCStyle.STREET, new DERUTF8String("UTF8")));
            rdns.add(new RDN(BCStyle.POSTAL_CODE, new DERUTF8String("UTF8")));
            rdns.add(new RDN(BCStyle.L, new DERUTF8String("UTF8")));
            rdns.add(new RDN(BCStyle.ST, new DERUTF8String("UTF8")));
            rdns.add(new RDN(BCStyle.C, new DERPrintableString("DE")));
            rdns.add(new RDN(BCStyle.DC, new DERIA5String("IA5")));

            X500Name name = new X500Name(rdns.toArray(new RDN[0]));

            X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), publicKey, name);

            caExtension.assertLintResult(LintResult.of(Status.PASS), new SubjectRdnsCorrectEncoding(), certificate);
        }

        {
            List<RDN> rdns = new ArrayList<>();

            rdns.add(new RDN(BCStyle.CN, new DERPrintableString("Printable")));
            rdns.add(new RDN(BCStyle.OU, new DERPrintableString("Printable")));
            rdns.add(new RDN(BCStyle.GIVENNAME, new DERPrintableString("Printable")));
            rdns.add(new RDN(BCStyle.SURNAME, new DERPrintableString("Printable")));
            rdns.add(new RDN(BCStyle.O, new DERPrintableString("Printable")));
            rdns.add(new RDN(BCStyle.STREET, new DERPrintableString("Printable")));
            rdns.add(new RDN(BCStyle.POSTAL_CODE, new DERPrintableString("Printable")));
            rdns.add(new RDN(BCStyle.L, new DERPrintableString("Printable")));
            rdns.add(new RDN(BCStyle.ST, new DERPrintableString("Printable")));
            rdns.add(new RDN(BCStyle.C, new DERPrintableString("DE")));
            rdns.add(new RDN(BCStyle.DC, new DERIA5String("IA5")));

            X500Name name = new X500Name(rdns.toArray(new RDN[0]));

            X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), publicKey, name);

            caExtension.assertLintResult(LintResult.of(Status.PASS), new SubjectRdnsCorrectEncoding(), certificate);
        }

    }

    @Test
    void notApplicableTest() throws Exception {
        X509Certificate certificate = caExtension.getCaCertificate();
        caExtension.assertLintResult(LintResult.of(Status.NA), new SubjectRdnsCorrectEncoding(), certificate);
    }

    @Test
    void errorTest() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        {
            List<RDN> rdns = new ArrayList<>();
            rdns.add(new RDN(BCStyle.CN, new DERIA5String("IA5")));
            X500Name name = new X500Name(rdns.toArray(new RDN[0]));
            X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), publicKey, name);
            caExtension.assertLintResult(LintResult.of(Status.ERROR), new SubjectRdnsCorrectEncoding(), certificate);
        }

        {
            List<RDN> rdns = new ArrayList<>();
            rdns.add(new RDN(BCStyle.OU, new DERIA5String("IA5")));
            X500Name name = new X500Name(rdns.toArray(new RDN[0]));
            X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), publicKey, name);
            caExtension.assertLintResult(LintResult.of(Status.ERROR), new SubjectRdnsCorrectEncoding(), certificate);
        }

        {
            List<RDN> rdns = new ArrayList<>();
            rdns.add(new RDN(BCStyle.GIVENNAME, new DERIA5String("IA5")));
            X500Name name = new X500Name(rdns.toArray(new RDN[0]));
            X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), publicKey, name);
            caExtension.assertLintResult(LintResult.of(Status.ERROR), new SubjectRdnsCorrectEncoding(), certificate);
        }

        {
            List<RDN> rdns = new ArrayList<>();
            rdns.add(new RDN(BCStyle.SURNAME, new DERIA5String("IA5")));
            X500Name name = new X500Name(rdns.toArray(new RDN[0]));
            X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), publicKey, name);
            caExtension.assertLintResult(LintResult.of(Status.ERROR), new SubjectRdnsCorrectEncoding(), certificate);
        }

        {
            List<RDN> rdns = new ArrayList<>();
            rdns.add(new RDN(BCStyle.O, new DERIA5String("IA5")));
            X500Name name = new X500Name(rdns.toArray(new RDN[0]));
            X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), publicKey, name);
            caExtension.assertLintResult(LintResult.of(Status.ERROR), new SubjectRdnsCorrectEncoding(), certificate);
        }

        {
            List<RDN> rdns = new ArrayList<>();
            rdns.add(new RDN(BCStyle.STREET, new DERIA5String("IA5")));
            X500Name name = new X500Name(rdns.toArray(new RDN[0]));
            X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), publicKey, name);
            caExtension.assertLintResult(LintResult.of(Status.ERROR), new SubjectRdnsCorrectEncoding(), certificate);
        }

        {
            List<RDN> rdns = new ArrayList<>();
            rdns.add(new RDN(BCStyle.POSTAL_CODE, new DERIA5String("IA5")));
            X500Name name = new X500Name(rdns.toArray(new RDN[0]));
            X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), publicKey, name);
            caExtension.assertLintResult(LintResult.of(Status.ERROR), new SubjectRdnsCorrectEncoding(), certificate);
        }

        {
            List<RDN> rdns = new ArrayList<>();
            rdns.add(new RDN(BCStyle.L, new DERIA5String("IA5")));
            X500Name name = new X500Name(rdns.toArray(new RDN[0]));
            X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), publicKey, name);
            caExtension.assertLintResult(LintResult.of(Status.ERROR), new SubjectRdnsCorrectEncoding(), certificate);
        }

        {
            List<RDN> rdns = new ArrayList<>();
            rdns.add(new RDN(BCStyle.ST, new DERIA5String("IA5")));
            X500Name name = new X500Name(rdns.toArray(new RDN[0]));
            X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), publicKey, name);
            caExtension.assertLintResult(LintResult.of(Status.ERROR), new SubjectRdnsCorrectEncoding(), certificate);
        }

        {
            List<RDN> rdns = new ArrayList<>();
            rdns.add(new RDN(BCStyle.C, new DERIA5String("DE")));
            X500Name name = new X500Name(rdns.toArray(new RDN[0]));
            X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), publicKey, name);
            caExtension.assertLintResult(LintResult.of(Status.ERROR), new SubjectRdnsCorrectEncoding(), certificate);
        }

        {
            List<RDN> rdns = new ArrayList<>();
            rdns.add(new RDN(BCStyle.DC, new DERUTF8String("UTF8")));
            X500Name name = new X500Name(rdns.toArray(new RDN[0]));
            X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), publicKey, name);
            caExtension.assertLintResult(LintResult.of(Status.ERROR), new SubjectRdnsCorrectEncoding(), certificate);
        }

    }

    public X509Certificate createTestCertificate(PublicKey caPublicKey, PrivateKey caPrivateKey, X500Name caIssuerDN, PublicKey publicKey, X500Name subjectDN)
            throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, NoSuchProviderException,
            SignatureException, InvalidKeyException {

        BigInteger serialNumber = new BigInteger(96, new Random());
        ZonedDateTime notBefore = ZonedDateTime.of(2023, 9, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey);
        SubjectKeyIdentifier ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension skie = new Extension(Extension.subjectKeyIdentifier, false, ski.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(caIssuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN, subjectPublicKeyInfo);
        certificateBuilder.addExtension(akie);
        certificateBuilder.addExtension(skie);
        certificateBuilder.addExtension(CAExtension.getCertificatePolicies("2.23.140.1.2.1"));
        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(CAExtension.SHA_256_WITH_RSA_ENCRYPTION);
        ContentSigner contentSigner = jcaContentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

    }

}
