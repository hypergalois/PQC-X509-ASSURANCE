package de.mtg.jzlint.ca;

import java.io.IOException;
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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Certificates for lints: e_mailbox_validated_allowed_subjectdn_attributes
 */
public class CreateCertificate017 {

    public static final String SHA_256_WITH_ECDSA = "SHA256WithECDSA";

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        X500Name caIssuerDN = new X500Name("CN=Lint CA, O=Lint, C=DE");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

//|Attribute               | Legacy     | Multipurpose| Strict
//                |commonName              | MAY        | MAY        	| MAY
//                |organizationName        | SHALL NOT  | SHALL NOT  	| SHALL NOT
//                |organizationalUnitName  | SHALL NOT  | SHALL NOT  	| SHALL NOT
//                |organizationIdentifier  | SHALL NOT  | SHALL NOT  	| SHALL NOT
//                |givenName               | SHALL NOT  | SHALL NOT  	| SHALL NOT
//                |surname                 | SHALL NOT  | SHALL NOT  	| SHALL NOT
//                |pseudonym               | SHALL NOT  | SHALL NOT  	| SHALL NOT
//                |serialNumber            | MAY        | MAY        	| MAY
//                |emailAddress            | MAY        | MAY        	| MAY
//                |title                   | SHALL NOT  | SHALL NOT  	| SHALL NOT
//                |streetAddress           | SHALL NOT  | SHALL NOT  	| SHALL NOT
//                |localityName            | SHALL NOT  | SHALL NOT  	| SHALL NOT
//                |stateOrProvinceName     | SHALL NOT  | SHALL NOT  	| SHALL NOT
//                |postalCode              | SHALL NOT  | SHALL NOT  	| SHALL NOT
//                |countryName             | SHALL NOT  | SHALL NOT  	| SHALL NOT
//                |Other                   | SHALL NOT  | SHALL NOT  	| SHALL NOT
        StringBuilder zlintTestVectors = new StringBuilder();
        {
            String name = "mailboxValidatedWithOrganizationInSubject";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X500Name subjectDN = new X500Name("O=Lint");
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, subjectDN);
            Files.write(Paths.get(nameDER), testCertificate.getEncoded());
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Error",
                    "Error - certificate is mailbox-validated and has organization in subject");
        }
        {
            String name = "mailboxValidatedWithCommonNameInSubject";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X500Name subjectDN = new X500Name("CN=test@example.com");
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, subjectDN);
            Files.write(Paths.get(nameDER), testCertificate.getEncoded());
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate is mailbox-validated and has commnonName in subject");
        }
        {
            String name = "mailboxValidatedWithEmailAddressInSubject";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X500Name subjectDN = new X500Name("E=test@example.com");
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, subjectDN);
            Files.write(Paths.get(nameDER), testCertificate.getEncoded());
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate is mailbox-validated and has emailAddress in subject");
        }
        {
            String name = "mailboxValidatedWithSerialNumberInSubject";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X500Name subjectDN = new X500Name("SERIALNUMBER=serialNumber");
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, subjectDN);
            Files.write(Paths.get(nameDER), testCertificate.getEncoded());
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate is mailbox-validated and has serialNumber in subject");
        }


        System.out.println(zlintTestVectors);
    }

    /**
     * For lint_subject_dir_attr_test
     */
    private static X509Certificate createTestCertificate(PrivateKey caPrivateKey, X500Name issuerDN, X500Name subjectDN) throws Exception {

        final String mailboxValidatedMultipurposeOID = "2.23.140.1.5.1.2";

        BigInteger serialNumber = new BigInteger(96, new Random());
        ZonedDateTime notBefore = ZonedDateTime.of(2023, 9, 1, 0, 0, 0, 0, ZoneId.of("UTC"));
        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        Extension certificatePolicies = getCertificatePolicies(mailboxValidatedMultipurposeOID);

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(issuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN,
                        subjectPublicKeyInfo);
        certificateBuilder.addExtension(certificatePolicies);
        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(SHA_256_WITH_ECDSA);
        ContentSigner contentSigner = jcaContentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);
    }

    private static Extension getCertificatePolicies(String policyOID) throws IOException {
        PolicyInformation[] policies = new PolicyInformation[1];
        List<PolicyInformation> policiesList = new ArrayList<>();
        PolicyInformation policyInformation = new PolicyInformation(new ASN1ObjectIdentifier(policyOID));
        policiesList.add(policyInformation);
        CertificatePolicies cps = new CertificatePolicies(policiesList.toArray(policies));
        return new Extension(Extension.certificatePolicies, false, cps.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

}
