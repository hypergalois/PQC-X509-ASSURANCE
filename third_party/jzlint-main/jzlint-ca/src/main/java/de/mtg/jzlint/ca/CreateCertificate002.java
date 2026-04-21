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
import java.util.Vector;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectDirectoryAttributes;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CreateCertificate002 {

    public static final String SHA_256_WITH_ECDSA = "SHA256WithECDSA";

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        X500Name caIssuerDN = new X500Name("CN=Lint CA, O=Lint, C=DE");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();


        {
            String name = "multipurposeWithSubjectDirectoryAttributes";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            final String mailboxValidatedMultipurposeOID = "2.23.140.1.5.1.2";
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, mailboxValidatedMultipurposeOID);

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }


    }

    /**
     * For lint_subject_dir_attr_test
     */
    private static X509Certificate createTestCertificate(PrivateKey caPrivateKey, X500Name issuerDN, String policyOID) throws Exception {

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

        // see RFC 3739
        //        id-pda-countryOfResidence   AttributeType ::= { id-pda 5 }
        //        CountryOfResidence ::=      PrintableString (SIZE (2))
        //                -- ISO 3166 Country Code
        Vector<Attribute> attributes = new Vector<>();
        DERPrintableString countryOfResidence = new DERPrintableString("DE");
        attributes.add(new Attribute(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.9.5"), new DERSet(countryOfResidence)));

        SubjectDirectoryAttributes sda = new SubjectDirectoryAttributes(attributes);
        Extension subjectDirectoryAttributes = new Extension(Extension.subjectDirectoryAttributes, false, sda.getEncoded());

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(issuerDN, serialNumber, notBeforeDate, noteAfterDate, new X500Name("CN=test@example.com"),
                        subjectPublicKeyInfo);
        certificateBuilder.addExtension(certificatePolicies);
        certificateBuilder.addExtension(subjectDirectoryAttributes);
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
