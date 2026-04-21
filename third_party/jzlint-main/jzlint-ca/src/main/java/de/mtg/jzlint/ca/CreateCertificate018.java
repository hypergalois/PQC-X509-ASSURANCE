package de.mtg.jzlint.ca;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Random;

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
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Certificates for lints: e_qcstatem_qctype_valid_one_only
 */
public class CreateCertificate018 {

    private static final String SHA_256_WITH_ECDSA = "SHA256WithECDSA";
    private static final ZonedDateTime NOT_BEFORE = ZonedDateTime.of(2025, 5, 1, 0, 0, 0, 0, ZoneId.of("UTC"));
    private static final X500Name CA_ISSUER_DN = new X500Name("CN=Lint CA, O=Lint, C=DE");
    private static PrivateKey caPrivateKey;

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        var keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        var algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        var keyPair = keyPairGenerator.generateKeyPair();
        caPrivateKey = keyPair.getPrivate();

        var zlintTestVectors = new StringBuilder();

        {
            var name = "qctWithEseal";
            var nameDER = String.format("%s.der", name);
            var namePEM = String.format("%s.pem", name);
            List<ASN1ObjectIdentifier> qcTypes = Arrays.asList(ETSIQCObjectIdentifiers.id_etsi_qct_eseal);
            var testCertificate = createTestCertificate(new X500Name("CN=ZLintTest"), qcTypes);

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate has only eseal qc type");
        }

        {
            var name = "qctWithEsealAndWeb";
            var nameDER = String.format("%s.der", name);
            var namePEM = String.format("%s.pem", name);
            List<ASN1ObjectIdentifier> qcTypes = Arrays.asList(
                    ETSIQCObjectIdentifiers.id_etsi_qct_eseal,
                    ETSIQCObjectIdentifiers.id_etsi_qct_web
            );
            var testCertificate = createTestCertificate(new X500Name("CN=ZLintTest"), qcTypes);

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Error",
                    "Error - certificate has eseal and web qc types");
        }

        {
            var name = "qctWithWrongType";
            var nameDER = String.format("%s.der", name);
            var namePEM = String.format("%s.pem", name);
            List<ASN1ObjectIdentifier> qcTypes = Arrays.asList(
                    ETSIQCObjectIdentifiers.id_etsi_qcs_LimiteValue
            );
            var testCertificate = createTestCertificate(new X500Name("CN=ZLintTest"), qcTypes);

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Error",
                    "Error - certificate has a wrong qcType in QcStatements");
        }

        System.out.println(zlintTestVectors);

    }

    private static X509Certificate createTestCertificate(X500Name subjectDN,
            List<ASN1ObjectIdentifier> qcTypes) throws Exception {

        var serialNumber = new BigInteger(96, new Random());

        var notBeforeDate = Date.from(NOT_BEFORE.toInstant());
        var noteAfterDate = Date.from(NOT_BEFORE.plusYears(1).toInstant());

        var keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        var algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        var keyPair = keyPairGenerator.generateKeyPair();
        var publicKey = keyPair.getPublic();
        var subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        var qcCertificatePolicies = new CertificatePolicies(new PolicyInformation[] {
                new PolicyInformation(new ASN1ObjectIdentifier("0.4.0.194112.1.5")),
                new PolicyInformation(new ASN1ObjectIdentifier("2.23.140.1.2.2")),
        });

        var qcStatement = new QCStatement(new ASN1ObjectIdentifier("0.4.0.1862.1.1"));
        var qcStatements = new ASN1EncodableVector();
        qcStatements.add(qcStatement);
        qcStatements.add(createEsi4QcStatement6(qcTypes));
        var qcSExtension = new DERSequence(qcStatements);
        var extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth);

        var certificateBuilder =
                new X509v3CertificateBuilder(CA_ISSUER_DN, serialNumber, notBeforeDate, noteAfterDate, subjectDN,
                        subjectPublicKeyInfo);

        certificateBuilder.addExtension(new Extension(Extension.qCStatements, false, new DEROctetString(qcSExtension)));
        certificateBuilder.addExtension(new Extension(Extension.certificatePolicies, true, new DEROctetString(qcCertificatePolicies)));
        certificateBuilder.addExtension(
                new Extension(Extension.extendedKeyUsage, false, extendedKeyUsage.toASN1Primitive().getEncoded(ASN1Encoding.DER)));

        var jcaContentSignerBuilder = new JcaContentSignerBuilder(SHA_256_WITH_ECDSA);
        var contentSigner = jcaContentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        var x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);
    }

    private static QCStatement createEsi4QcStatement6(List<ASN1ObjectIdentifier> oids) {
        var vector = new ASN1EncodableVector();
        oids.forEach(oid -> vector.add(oid));
        return new QCStatement(ETSIQCObjectIdentifiers.id_etsi_qcs_QcType, new DERSequence(vector));
    }

}
