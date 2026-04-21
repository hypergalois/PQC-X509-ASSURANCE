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

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.DERUniversalString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
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
import org.bouncycastle.util.encoders.Hex;


/**
 * Certificates for lint: e_subject_rdns_correct_encoding
 */
public class CreateCertificate007 {


    public static final String SHA_256_WITH_ECDSA = "SHA256WithECDSA";

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        X500Name caIssuerDN = new X500Name("CN=Lint CA, O=Lint, C=DE");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        DERUTF8String utf8String = new DERUTF8String("UTF8String");
        DERPrintableString printableString = new DERPrintableString("PrintableString");
        DERT61String teletexString = new DERT61String("TeletexString");
        DERIA5String ia5String = new DERIA5String("IA5String");
        DERUniversalString universalString = new DERUniversalString(Hex.decode("00000055"));
        DERBMPString bmpString = new DERBMPString("BMPString");


        StringBuilder opensslAppender =  new StringBuilder();

        issueWronglyEncodedCertificate("DC", BCStyle.DC, utf8String, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "domainComponent", "UTF8String");
        issueWronglyEncodedCertificate("C", BCStyle.C,  new DERUTF8String("DE"), privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "countryName", "UTF8String");
        issueWronglyEncodedCertificate("ST", BCStyle.ST, teletexString, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "stateOrProvinceName", "TeletexString");
        issueWronglyEncodedCertificate("L", BCStyle.L, ia5String, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "localityName", "IA5String");
        issueWronglyEncodedCertificate("PostalCode", BCStyle.POSTAL_CODE, universalString, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "postalCode", "UniversalString");
        issueWronglyEncodedCertificate("Street", BCStyle.STREET, bmpString, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "streetAddress", "BMPString");
        issueWronglyEncodedCertificate("O", BCStyle.O, teletexString, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "organizationName", "TeletexString");
        issueWronglyEncodedCertificate("Surname", BCStyle.SURNAME, ia5String, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "surname", "IA5String");
        issueWronglyEncodedCertificate("GivenName", BCStyle.GIVENNAME, bmpString, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "givenName", "BMPString");
        issueWronglyEncodedCertificate("OU", BCStyle.OU, bmpString, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "organizationalUnitName", "BMPString");
        issueWronglyEncodedCertificate("CN", BCStyle.CN, universalString, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "commonName", "UniversalString");

        issueWronglyEncodedCertificate("BusinessCategory", BCStyle.BUSINESS_CATEGORY, teletexString, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "businessCategory", "TeletexString");
        issueWronglyEncodedCertificate("jurC", new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3"), bmpString, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "jurisdictionCountry", "BMPString");
        issueWronglyEncodedCertificate("jurST", new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.2"), ia5String, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "jurisdictionStateOrProvince", "IA5String");
        issueWronglyEncodedCertificate("jurL", new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.1"), bmpString, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "jurisdictionLocality", "BMPString");
        issueWronglyEncodedCertificate("SerialNumber", BCStyle.SERIALNUMBER, universalString, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "serialNumber", "UniversalString");
        issueWronglyEncodedCertificate("OrganizationIdentifier", BCStyle.ORGANIZATION_IDENTIFIER, teletexString, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, "organizationIdentifier", "TeletexString");



        issueCorrectEncodedCertificate("DC", BCStyle.DC, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, ia5String);
        issueCorrectEncodedCertificate("C", BCStyle.C, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, printableString);
        issueCorrectEncodedCertificate("ST", BCStyle.ST, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, utf8String, printableString);
        issueCorrectEncodedCertificate("L", BCStyle.L, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, utf8String, printableString);
        issueCorrectEncodedCertificate("PostalCode", BCStyle.POSTAL_CODE, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, utf8String, printableString);
        issueCorrectEncodedCertificate("Street", BCStyle.STREET, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, utf8String, printableString);
        issueCorrectEncodedCertificate("O", BCStyle.O, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, utf8String, printableString);
        issueCorrectEncodedCertificate("Surname", BCStyle.SURNAME, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, utf8String, printableString);
        issueCorrectEncodedCertificate("GivenName", BCStyle.GIVENNAME, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, utf8String, printableString);
        issueCorrectEncodedCertificate("OU", BCStyle.OU, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, utf8String, printableString);
        issueCorrectEncodedCertificate("CN", BCStyle.CN, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, utf8String, printableString);

        issueCorrectEncodedCertificate("BusinessCategory", BCStyle.BUSINESS_CATEGORY, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, utf8String, printableString);
        issueCorrectEncodedCertificate("jurC", new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.3"), privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, printableString);
        issueCorrectEncodedCertificate("jurST", new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.2"), privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, utf8String, printableString);
        issueCorrectEncodedCertificate("jurL", new ASN1ObjectIdentifier("1.3.6.1.4.1.311.60.2.1.1"), privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, utf8String, printableString);
        issueCorrectEncodedCertificate("SerialNumber", BCStyle.SERIALNUMBER, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, printableString);
        issueCorrectEncodedCertificate("OrganizationIdentifier", BCStyle.ORGANIZATION_IDENTIFIER, privateKey, caIssuerDN, subjectPublicKeyInfo, opensslAppender, utf8String, printableString);



        System.out.println(opensslAppender);

    }

    private static void issueWronglyEncodedCertificate(String attributeName, ASN1ObjectIdentifier oid, ASN1Encodable value, PrivateKey privateKey, X500Name caIssuerDN,
            SubjectPublicKeyInfo subjectPublicKeyInfo, StringBuilder opensslAppender, String errorAttributeName, String encoding)
            throws Exception {
        RDN rdn = new RDN(oid, value);

        List<RDN> rdns = new ArrayList<>();
        rdns.add(rdn);
        X500Name subjectDN = new X500Name(rdns.toArray(new RDN[0]));

        String name = "subject%sWrongEncoding".formatted(attributeName);
        String nameDER = String.format("%s.der", name);
        String namePEM = String.format("%s.pem", name);
        X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, subjectDN, subjectPublicKeyInfo);

        Files.write(Paths.get(nameDER), testCertificate.getEncoded());


        System.out.println("{");
        System.out.print("\"");
        System.out.print(namePEM);
        System.out.println("\",");
        System.out.println("lint.Error,");
        System.out.printf("\"Attribute %s in subjectDN has the wrong encoding %s\",%n", errorAttributeName, encoding);
        System.out.println("},");




        opensslAppender.append(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        opensslAppender.append("\n");
        //System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
    }


    private static void issueCorrectEncodedCertificate(String attributeName, ASN1ObjectIdentifier oid, PrivateKey privateKey, X500Name caIssuerDN,
            SubjectPublicKeyInfo subjectPublicKeyInfo, StringBuilder opensslAppender, ASN1Encodable... allowedValues)
            throws Exception {

        List<RDN> rdns = new ArrayList<>();
        for (ASN1Encodable allowedValue : allowedValues) {
            RDN rdn = new RDN(oid, allowedValue);
            rdns.add(rdn);
        }

        X500Name subjectDN = new X500Name(rdns.toArray(new RDN[0]));

        String name = "subject%sCorrectEncoding".formatted(attributeName);
        String nameDER = String.format("%s.der", name);
        String namePEM = String.format("%s.pem", name);
        X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, subjectDN, subjectPublicKeyInfo);

        Files.write(Paths.get(nameDER), testCertificate.getEncoded());

        System.out.println("{");
        System.out.print("\"");
        System.out.print(namePEM);
        System.out.println("\",");
        System.out.println("lint.Pass,");
        System.out.println("\"\",");
        System.out.println("},");

        opensslAppender.append(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        opensslAppender.append("\n");
    }


    /**
     * For lint_subject_dir_attr_test
     */
    private static X509Certificate createTestCertificate(PrivateKey caPrivateKey, X500Name issuerDN, X500Name subjectDN,
            SubjectPublicKeyInfo subjectPublicKeyInfo) throws Exception {

        BigInteger serialNumber = new BigInteger(96, new Random());
        ZonedDateTime notBefore = ZonedDateTime.of(2023, 9, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        Extension certificatePolicies = getCertificatePolicies("2.23.140.1.2.1");

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(issuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN, subjectPublicKeyInfo);
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
