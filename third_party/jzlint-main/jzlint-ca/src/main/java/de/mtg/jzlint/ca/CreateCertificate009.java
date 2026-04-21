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
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
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
 * Certificates for lints: e_aia_ocsp_must_be_present, e_aia_ocsp_must_have_http_only
 */
public class CreateCertificate009 {

    public static final String SHA_256_WITH_ECDSA = "SHA256WithECDSA";

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        X500Name caIssuerDN = new X500Name("CN=Lint CA, O=Lint, C=DE");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        ZonedDateTime notBefore = ZonedDateTime.of(2023, 9, 15, 0, 0, 0, 0, ZoneId.of("UTC"));

        {
            String name = "caCertificateAfter15092023";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createCACertificate(privateKey, caIssuerDN, notBefore);

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }

        {
            String name = "aiaOCSPOneHTTPOneLDAP";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBefore, "http://ocsp.example.com/ocsp", "ldap://ocsp.example.com/ocsp");

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }

        {
            String name = "aiaOCSPWithHTTPSURL";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBefore, "https://ocsp.example.com/ocsp");

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }

        {
            String name = "aiaOCSPHttpOnlyNE";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            ZonedDateTime notBeforeNE = ZonedDateTime.of(2023, 9, 14, 23, 59, 59, 0, ZoneId.of("UTC"));
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBeforeNE, "http://ocsp.example.com/ocsp");

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }
        
    }

    private static X509Certificate createCACertificate(PrivateKey caPrivateKey, X500Name issuerDN, ZonedDateTime notBefore)
            throws Exception {

        BigInteger serialNumber = new BigInteger(96, new Random());

        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        Extension certificatePolicies = getCertificatePolicies("2.23.140.1.2.1");

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(issuerDN, serialNumber, notBeforeDate, noteAfterDate, new X500Name(""),
                        subjectPublicKeyInfo);
        certificateBuilder.addExtension(certificatePolicies);
        BasicConstraints bc = new BasicConstraints(true);
        Extension basicConstraints = new Extension(Extension.basicConstraints, true, bc.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        certificateBuilder.addExtension(basicConstraints);

        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(SHA_256_WITH_ECDSA);
        ContentSigner contentSigner = jcaContentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);
    }

    private static X509Certificate createTestCertificate(PrivateKey caPrivateKey, X500Name issuerDN, ZonedDateTime notBefore, String... uris)
            throws Exception {

        BigInteger serialNumber = new BigInteger(96, new Random());

        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        Extension certificatePolicies = getCertificatePolicies("2.23.140.1.2.1");

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(issuerDN, serialNumber, notBeforeDate, noteAfterDate, new X500Name(""),
                        subjectPublicKeyInfo);
        certificateBuilder.addExtension(certificatePolicies);

        if (uris == null) {
            // do not add extension
        } else if (uris.length == 1 && uris[0].isBlank()) {
            AccessDescription[] accessDescriptions = new AccessDescription[1];

            GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, "http://issuers.example.com/");
            AccessDescription accessDescription = new AccessDescription(AccessDescription.id_ad_caIssuers, generalName);
            accessDescriptions[0] = accessDescription;

            AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(accessDescriptions);
            byte[] encodedExtension = authorityInformationAccess.toASN1Primitive().getEncoded(ASN1Encoding.DER);
            Extension aia = new Extension(Extension.authorityInfoAccess, false, encodedExtension);
            certificateBuilder.addExtension(aia);
        } else {
            Extension aia = getAuthorityInformationAccess(uris);
            certificateBuilder.addExtension(aia);
        }

        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder(SHA_256_WITH_ECDSA);
        ContentSigner contentSigner = jcaContentSignerBuilder.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);
    }

    private static Extension getAuthorityInformationAccess(String[] uris) throws IOException {
        AccessDescription[] accessDescriptions = new AccessDescription[uris.length];
        int counter = 0;
        for (String uri : uris) {
            GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, uri);
            AccessDescription accessDescription = new AccessDescription(AccessDescription.id_ad_ocsp, generalName);
            accessDescriptions[counter] = accessDescription;
            counter = counter + 1;
        }
        AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(accessDescriptions);
        return new Extension(Extension.authorityInfoAccess, false, authorityInformationAccess.toASN1Primitive().getEncoded(ASN1Encoding.DER));
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
