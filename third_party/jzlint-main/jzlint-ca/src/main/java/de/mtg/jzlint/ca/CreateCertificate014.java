package de.mtg.jzlint.ca;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;


/**
 * Certificates for lints: e_qcstatem_correct_national_scheme
 */
public class CreateCertificate014 {

    public static final String SHA_256_WITH_ECDSA = "SHA256WithECDSA";

    public static final ASN1ObjectIdentifier idEtsiQcsSemanticsIdNatural = new ASN1ObjectIdentifier("0.4.0.194121.1.1");
    public static final ASN1ObjectIdentifier idEtsiQcsSemanticsIdLegal = new ASN1ObjectIdentifier("0.4.0.194121.1.2");

    public static final String COPY_TO_PATH = "/cygdrive/cijzlint/zlint/v3/testdata";

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        X500Name caIssuerDN = new X500Name("CN=Lint CA, O=Lint, C=DE");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPairGenerator.generateKeyPair().getPublic().getEncoded());

        StringBuilder zlintTestVectors = new StringBuilder();

        {
            String name = "qcNaturalNoNationalScheme";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);

            X509Certificate testCertificate = createNaturalTestCertificate(privateKey, caIssuerDN, subjectPublicKeyInfo, "PASSK-P3000180");
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "NA",
                    "NA - certificate has the natural person semantics identifier and no national scheme value");
        }


        {
            String name = "qcNaturalCorrectNationalScheme";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);

            X509Certificate testCertificate = createNaturalTestCertificate(privateKey, caIssuerDN, subjectPublicKeyInfo, "EI:SE-5567971433");
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate has the natural person semantics identifier and a correct national scheme value");
        }


        {
            String name = "qcNaturalNotCorrectScheme";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);

            X509Certificate testCertificate = createNaturalTestCertificate(privateKey, caIssuerDN, subjectPublicKeyInfo, "EI:NOTCORRECTSCHEME");
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Error",
                    "Error - certificate has the natural person semantics identifier and a wrong national scheme value");
        }

        {
            String name = "qcLegalNoNationalScheme";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);

            X509Certificate testCertificate = createLegalTestCertificate(privateKey, caIssuerDN, subjectPublicKeyInfo, "PASSK-P3000180");
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "NA",
                    "NA - certificate has the legal person semantics identifier and no national scheme value");
        }

        {
            String name = "qcLegalCorrectNationalScheme";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);

            X509Certificate testCertificate = createLegalTestCertificate(privateKey, caIssuerDN, subjectPublicKeyInfo, "EI:SE-5567971433");
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate has the legal person semantics identifier and a correct national scheme value");
        }

        {
            String name = "qcLegalNotCorrectScheme";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);

            X509Certificate testCertificate = createLegalTestCertificate(privateKey, caIssuerDN, subjectPublicKeyInfo, "EI:A");
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Error",
                    "Error - certificate has the legal person semantics identifier and a wrong national scheme value");
        }


        System.out.println();
        System.out.println();
        System.out.println(zlintTestVectors);
    }

    private static X509Certificate createNaturalTestCertificate(
            PrivateKey caPrivateKey,
            X500Name issuerDN,
            SubjectPublicKeyInfo subjectPublicKeyInfo,
            String serialNumberValue)
            throws Exception {

        BigInteger serialNumber = new BigInteger(96, new Random());
        ZonedDateTime notBefore = ZonedDateTime.of(2025, 2, 18, 0, 0, 0, 0, ZoneId.of("UTC"));

        DERPrintableString value = new DERPrintableString(serialNumberValue);
        RDN rdn = new RDN(BCStyle.SERIALNUMBER, value);
        List<RDN> rdns = new ArrayList<>();
        rdns.add(rdn);
        X500Name subjectDN = new X500Name(rdns.toArray(new RDN[0]));

        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        //        QCStatements ::= SEQUENCE OF QCStatement
        //        QCStatement ::= SEQUENCE {
        //            statementId   QC-STATEMENT.&Id({SupportedStatements}),
        //                    statementInfo QC-STATEMENT.&Type
        //                    ({SupportedStatements}{@statementId}) OPTIONAL }
        ASN1EncodableVector qcStatements = new ASN1EncodableVector();
        qcStatements.add(createQcStatement2Natural());
        ASN1Encodable qcSExtension = new DERSequence(qcStatements);

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(issuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN,
                        subjectPublicKeyInfo);

        certificateBuilder.addExtension(new Extension(Extension.qCStatements, false, new DEROctetString(qcSExtension)));

        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(SHA_256_WITH_ECDSA);
        ContentSigner contentSigner = jcaContentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);
    }

    private static X509Certificate createLegalTestCertificate(
            PrivateKey caPrivateKey,
            X500Name issuerDN,
            SubjectPublicKeyInfo subjectPublicKeyInfo,
            String organizationIdentifierValue)
            throws Exception {

        BigInteger serialNumber = new BigInteger(96, new Random());
        ZonedDateTime notBefore = ZonedDateTime.of(2025, 2, 18, 0, 0, 0, 0, ZoneId.of("UTC"));

        DERUTF8String value = new DERUTF8String(organizationIdentifierValue);
        RDN rdn = new RDN(BCStyle.ORGANIZATION_IDENTIFIER, value);
        List<RDN> rdns = new ArrayList<>();
        rdns.add(rdn);
        X500Name subjectDN = new X500Name(rdns.toArray(new RDN[0]));

        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        //        QCStatements ::= SEQUENCE OF QCStatement
        //        QCStatement ::= SEQUENCE {
        //            statementId   QC-STATEMENT.&Id({SupportedStatements}),
        //                    statementInfo QC-STATEMENT.&Type
        //                    ({SupportedStatements}{@statementId}) OPTIONAL }
        ASN1EncodableVector qcStatements = new ASN1EncodableVector();
        qcStatements.add(createQcStatement2Legal());
        ASN1Encodable qcSExtension = new DERSequence(qcStatements);

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(issuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN,
                        subjectPublicKeyInfo);

        certificateBuilder.addExtension(new Extension(Extension.qCStatements, false, new DEROctetString(qcSExtension)));

        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(SHA_256_WITH_ECDSA);
        ContentSigner contentSigner = jcaContentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);
    }

    private static QCStatement createQcStatement2Natural() {
        //        SemanticsInformation ::= SEQUENCE {
        //            semanticsIdentifier         OBJECT IDENTIFIER OPTIONAL,
        //            nameRegistrationAuthorities NameRegistrationAuthorities OPTIONAL
        //        }(WITH COMPONENTS {..., semanticsIdentifier PRESENT}|
        //        WITH COMPONENTS {..., nameRegistrationAuthorities PRESENT})
        //        NameRegistrationAuthorities ::= SEQUENCE SIZE (1..MAX) OF GeneralName
        ASN1EncodableVector semanticsInformation = new ASN1EncodableVector();
        semanticsInformation.add(idEtsiQcsSemanticsIdNatural);
        return new QCStatement(QCStatement.id_qcs_pkixQCSyntax_v2, new DERSequence(semanticsInformation));
    }

    private static QCStatement createQcStatement2Legal() {
        ASN1EncodableVector semanticsInformation = new ASN1EncodableVector();
        semanticsInformation.add(idEtsiQcsSemanticsIdLegal);
        return new QCStatement(QCStatement.id_qcs_pkixQCSyntax_v2, new DERSequence(semanticsInformation));
    }

}
