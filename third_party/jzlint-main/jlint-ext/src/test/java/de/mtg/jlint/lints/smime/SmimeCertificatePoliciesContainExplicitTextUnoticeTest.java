package de.mtg.jlint.lints.smime;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;
import java.util.Vector;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DisplayText;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.NoticeReference;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.UserNotice;
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

class SmimeCertificatePoliciesContainExplicitTextUnoticeTest {

    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void passTest() throws Exception {
        X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), false);
        caExtension.assertLintResult(LintResult.of(Status.PASS), new SmimeCertificatePoliciesContainExplicitTextUnotice(), certificate);
    }

    @Test
    void errorTest() throws Exception {
        X509Certificate certificate = createTestCertificate(caExtension.getCaPublicKey(), caExtension.getCaPrivateKey(), caExtension.getIsserDN(), true);
        caExtension.assertLintResult(LintResult.of(Status.ERROR), new SmimeCertificatePoliciesContainExplicitTextUnotice(), certificate);
    }

    @Test
    void notApplicableTest() throws Exception {
        X509Certificate certificate = caExtension.getCaCertificate();
        caExtension.assertLintResult(LintResult.of(Status.NA), new SmimeCertificatePoliciesContainExplicitTextUnotice(), certificate);
        certificate = caExtension.createSMimeEECertificate();
        caExtension.assertLintResult(LintResult.of(Status.NA), new SmimeCertificatePoliciesContainExplicitTextUnotice(), certificate);
    }

    private X509Certificate createTestCertificate(PublicKey caPublicKey, PrivateKey caPrivateKey, X500Name caIssuerDN, boolean isNoticeRef) throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, NoSuchProviderException {

        BigInteger serialNumber = new BigInteger(96, new Random());
        ZonedDateTime notBefore = ZonedDateTime.of(2023, 9, 1, 0, 0, 0, 0, ZoneId.of("UTC"));
        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        X500Name subjectDN = new X500Name("CN=Certificate, O=Lint, C=DE");

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey);
        SubjectKeyIdentifier ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension skie = new Extension(Extension.subjectKeyIdentifier, false, ski.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        List<PolicyInformation> policiesList = new ArrayList<>();

        UserNotice unoticeValue;

        if (isNoticeRef) {
            Vector vector = new Vector();
            vector.add(1);
            ASN1EncodableVector encodableVector = new ASN1EncodableVector();
            encodableVector.add(new NoticeReference("displayText", vector));
            unoticeValue = UserNotice.getInstance(new DERSequence(encodableVector));
        } else {
            ASN1EncodableVector encodableVector = new ASN1EncodableVector();
            encodableVector.add(new DisplayText("displayText"));
            unoticeValue = UserNotice.getInstance(new DERSequence(encodableVector));
        }

        PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(PolicyQualifierId.id_qt_unotice, unoticeValue);

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(policyQualifierInfo);
        PolicyInformation[] policies = new PolicyInformation[1];
        PolicyInformation policyInformation = new PolicyInformation(new ASN1ObjectIdentifier("2.23.140.1.5.1.2"), new DERSequence(vector));
        policiesList.add(policyInformation);
        CertificatePolicies cps = new CertificatePolicies(policiesList.toArray(policies));

        Extension certificatePolicies = new Extension(Extension.certificatePolicies, false, cps.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection);

        Extension eku = new Extension(Extension.extendedKeyUsage, false, extendedKeyUsage.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(caIssuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN, subjectPublicKeyInfo);
        certificateBuilder.addExtension(akie);
        certificateBuilder.addExtension(skie);
        certificateBuilder.addExtension(eku);
        certificateBuilder.addExtension(certificatePolicies);
        ContentSigner contentSigner = new JcaContentSignerBuilder(CAExtension.SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

    }

}
