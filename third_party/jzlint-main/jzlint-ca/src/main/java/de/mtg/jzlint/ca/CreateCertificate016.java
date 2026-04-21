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
 * Certificates for lints: e_subject_country_name
 */
public class CreateCertificate016 {

    public static final String SHA_256_WITH_ECDSA = "SHA256WithECDSA";

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        X500Name caIssuerDN = new X500Name("CN=Lint CA, O=Lint, C=DE");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        StringBuilder zlintTestVectors = new StringBuilder();
        {
            String name = "organizationValidatedWithInvalidCountry";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X500Name subjectDN = new X500Name("C=YY");
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, subjectDN, "2.23.140.1.5.2.2");
            Files.write(Paths.get(nameDER), testCertificate.getEncoded());
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Error",
                    "Error - certificate is organization-validated and has an invalid country in countryName");
        }
        {
            String name = "individualValidatedWithValidCountry";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X500Name subjectDN = new X500Name("C=DE");
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, subjectDN, "2.23.140.1.5.4.3");
            Files.write(Paths.get(nameDER), testCertificate.getEncoded());
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate is individual-validated and has an valid country in countryName");
        }
        {
            String name = "individualValidatedWithXXCodeInCountry";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X500Name subjectDN = new X500Name("C=XX");
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, subjectDN, "2.23.140.1.5.4.3");
            Files.write(Paths.get(nameDER), testCertificate.getEncoded());
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate is individual-validated and has the valid XX code in countryName");
        }

        System.out.println(zlintTestVectors);
    }

    /**
     * For lint_subject_dir_attr_test
     */
    private static X509Certificate createTestCertificate(PrivateKey caPrivateKey, X500Name issuerDN, X500Name subjectDN, String policyOID) throws Exception {


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

        Extension certificatePolicies = getCertificatePolicies(policyOID);

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
