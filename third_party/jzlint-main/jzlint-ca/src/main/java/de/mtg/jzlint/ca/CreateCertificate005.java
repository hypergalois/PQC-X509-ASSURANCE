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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CreateCertificate005 {

    public static final String SHA_256_WITH_ECDSA = "SHA256WithECDSA";

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        X500Name caIssuerDN = new X500Name("CN=Lint CA, O=Lint, C=DE");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        PublicKey rootPublicKey = rootKeyPair.getPublic();
        PrivateKey rootPrivateKey = rootKeyPair.getPrivate();

        {
            X509Certificate testCertificate = createTestCertificate(rootPublicKey, rootPrivateKey, caIssuerDN, "CN=Lint, C=DE");
            String name = "dvWithCNAndCountry";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }

        {
            X509Certificate testCertificate = createTestCertificate(rootPublicKey, rootPrivateKey, caIssuerDN, "CN=Lint, serialNumber=1, C=DE");
            String name = "dvWithSerialNumber";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }

        {
            X509Certificate testCertificate = createTestCertificate(rootPublicKey, rootPrivateKey, caIssuerDN, "CN=Lint, O=ZLint, C=DE");
            String name = "dvWithOrganization";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }

        {
            X509Certificate testCertificate = createTestCertificate(rootPublicKey, rootPrivateKey, caIssuerDN, "C=DE");
            String name = "dvCountry";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }

        {
            X509Certificate testCertificate = createTestCertificate(rootPublicKey, rootPrivateKey, caIssuerDN, null);
            String name = "dvEmptySubject";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }

    }

    /**
     * test certificate for lint_sub_cert_aia_contains_internal_names.go
     *
     * @param caPublicKey
     * @param caPrivateKey
     * @param issuerDN
     *
     * @return
     *
     * @throws Exception
     */
    private static X509Certificate createTestCertificate(PublicKey caPublicKey, PrivateKey caPrivateKey, X500Name issuerDN, String subjectDN)
            throws Exception {

        BigInteger serialNumber = new BigInteger(96, new Random());
        ZonedDateTime notBefore = ZonedDateTime.of(2023, 9, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        X500Name x500SubjectDN;
        if (subjectDN != null) {
            x500SubjectDN = new X500Name(subjectDN);
        } else {
            x500SubjectDN = new X500Name("");
        }

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey);
        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        PolicyInformation[] policies = new PolicyInformation[1];
        List<PolicyInformation> policiesList = new ArrayList<>();
        PolicyInformation policyInformation = new PolicyInformation(new ASN1ObjectIdentifier("2.23.140.1.2.1"));
        policiesList.add(policyInformation);
        CertificatePolicies cps = new CertificatePolicies(policiesList.toArray(policies));
        Extension cp = new Extension(Extension.certificatePolicies, false, cps.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(issuerDN, serialNumber, notBeforeDate, noteAfterDate, x500SubjectDN, subjectPublicKeyInfo);
        certificateBuilder.addExtension(akie);
        certificateBuilder.addExtension(cp);

        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(SHA_256_WITH_ECDSA);
        ContentSigner contentSigner = jcaContentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

    }

}
