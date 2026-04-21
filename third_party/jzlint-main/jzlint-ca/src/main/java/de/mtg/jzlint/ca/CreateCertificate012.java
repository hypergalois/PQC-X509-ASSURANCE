package de.mtg.jzlint.ca;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.qualified.ETSIQCObjectIdentifiers;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


/**
 * Certificates for lints: e_qcstatem_qctype_smime
 */
public class CreateCertificate012 {

    public static final String SHA_256_WITH_ECDSA = "SHA256WithECDSA";

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        X500Name caIssuerDN = new X500Name("CN=Lint CA, O=Lint, C=DE");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        ZonedDateTime notBefore = ZonedDateTime.of(2025, 2, 18, 0, 0, 0, 0, ZoneId.of("UTC"));

        {
            String name = "qcSmimeNatural";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate =
                    createTestCertificate(privateKey, caIssuerDN, notBefore, new X500Name("CN=test"), "0.4.0.194112.1.0", true);//QCP-n

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }
        {
            String name = "qcSmimeLegal";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate =
                    createTestCertificate(privateKey, caIssuerDN, notBefore, new X500Name("CN=test"), "0.4.0.194112.1.1", true);//QCP-l

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }

        {
            String name = "qcLegal";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate =
                    createTestCertificate(privateKey, caIssuerDN, notBefore, new X500Name("CN=test"), "0.4.0.194112.1.1", false);//QCP-l

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }


        {
            String name = "qcSmimeWeb";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate =
                    createErrorTestCertificate(privateKey, caIssuerDN, notBefore, new X500Name("CN=test"), "0.4.0.194112.1.1", true);//QCP-l

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }


    }

    private static X509Certificate createTestCertificate(PrivateKey caPrivateKey, X500Name issuerDN, ZonedDateTime notBefore, X500Name subjectDN,
            String policyOID, boolean withMIMEPolicy)
            throws Exception {

        BigInteger serialNumber = new BigInteger(96, new Random());

        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(3).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        CertificatePolicies qcCertificatePolicies;
        if (withMIMEPolicy) {
            qcCertificatePolicies = new CertificatePolicies(new PolicyInformation[] {
                    new PolicyInformation(new ASN1ObjectIdentifier(policyOID)),
                    new PolicyInformation(new ASN1ObjectIdentifier("2.23.140.1.5.1.2")), // mailboxValidatedMultipurposeOID
            });
        } else {
            qcCertificatePolicies = new CertificatePolicies(new PolicyInformation[] {new PolicyInformation(new ASN1ObjectIdentifier(policyOID))});
        }

        QCStatement qcStatement = new QCStatement(new ASN1ObjectIdentifier("0.4.0.1862.1.1"));
        ASN1EncodableVector qcStatements = new ASN1EncodableVector();
        qcStatements.add(qcStatement);
        qcStatements.add(createEsi4QcStatement6(ETSIQCObjectIdentifiers.id_etsi_qct_eseal));
        ASN1Encodable qcSExtension = new DERSequence(qcStatements);
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection);

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(issuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN,
                        subjectPublicKeyInfo);

        certificateBuilder.addExtension(new Extension(Extension.qCStatements, false, new DEROctetString(qcSExtension)));
        certificateBuilder.addExtension(new Extension(Extension.certificatePolicies, true, new DEROctetString(qcCertificatePolicies)));
        certificateBuilder.addExtension(new Extension(Extension.extendedKeyUsage, false, extendedKeyUsage.toASN1Primitive().getEncoded(ASN1Encoding.DER)));

        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(SHA_256_WITH_ECDSA);
        ContentSigner contentSigner = jcaContentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);
    }


    private static X509Certificate createErrorTestCertificate(PrivateKey caPrivateKey, X500Name issuerDN, ZonedDateTime notBefore, X500Name subjectDN,
            String policyOID, boolean withMIMEPolicy)
            throws Exception {

        BigInteger serialNumber = new BigInteger(96, new Random());

        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(3).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        CertificatePolicies qcCertificatePolicies;
        if (withMIMEPolicy) {
            qcCertificatePolicies = new CertificatePolicies(new PolicyInformation[] {
                    new PolicyInformation(new ASN1ObjectIdentifier(policyOID)),
                    new PolicyInformation(new ASN1ObjectIdentifier("2.23.140.1.5.1.2")), // mailboxValidatedMultipurposeOID
            });
        } else {
            qcCertificatePolicies = new CertificatePolicies(new PolicyInformation[] {new PolicyInformation(new ASN1ObjectIdentifier(policyOID))});
        }

        QCStatement qcStatement = new QCStatement(new ASN1ObjectIdentifier("0.4.0.1862.1.1"));
        ASN1EncodableVector qcStatements = new ASN1EncodableVector();
        qcStatements.add(qcStatement);
        qcStatements.add(createEsi4QcStatement6(ETSIQCObjectIdentifiers.id_etsi_qct_web));
        ASN1Encodable qcSExtension = new DERSequence(qcStatements);
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection);

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(issuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN,
                        subjectPublicKeyInfo);

        certificateBuilder.addExtension(new Extension(Extension.qCStatements, false, new DEROctetString(qcSExtension)));
        certificateBuilder.addExtension(new Extension(Extension.certificatePolicies, true, new DEROctetString(qcCertificatePolicies)));
        certificateBuilder.addExtension(new Extension(Extension.extendedKeyUsage, false, extendedKeyUsage.toASN1Primitive().getEncoded(ASN1Encoding.DER)));

        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(SHA_256_WITH_ECDSA);
        ContentSigner contentSigner = jcaContentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);
    }

    private static QCStatement createEsi4QcStatement6(ASN1ObjectIdentifier oid) {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(oid);

        return new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType, new DERSequence(vector));
    }

}
