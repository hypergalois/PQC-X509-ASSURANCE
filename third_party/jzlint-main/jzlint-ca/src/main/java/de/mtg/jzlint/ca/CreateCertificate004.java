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
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Random;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CreateCertificate004 {

    public static final String SHA_256_WITH_ECDSA = "SHA256WithECDSA";

    public static void main(String[] args) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        X500Name caIssuerDN = new X500Name("CN=Lint CA, O=Lint, C=DE");

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        AlgorithmParameterSpec algParSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        keyPairGenerator.initialize(algParSpec);

        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        PrivateKey rootPrivateKey = rootKeyPair.getPrivate();

        {
            String name = "sponsorValidatedMultipurposeEmailInSubjectNotInSAN";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);

            X500Name subjectDN = new X500Name("E=zlint@example.com, O=Lint, C=DE");
            X509Certificate testCertificate = createTestCertificate(rootPrivateKey, caIssuerDN, subjectDN, "diff", null);

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }

        {
            String name = "sponsorValidatedMultipurposePersonalNameInCN";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);

            X500Name subjectDN = new X500Name("CN=Personal Name, O=Lint, C=DE");
            X509Certificate testCertificate = createTestCertificate(rootPrivateKey, caIssuerDN, subjectDN, "sanonly", null);

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }

        {
            String name = "WithOnlySANEmail";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);

            X509Certificate testCertificate = createTestCertificate(rootPrivateKey, caIssuerDN, new X500Name(""), "test", null);

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }

        {
            String name = "WithOnlySANOtherName";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);

            X509Certificate testCertificate = createTestCertificate(rootPrivateKey, caIssuerDN, new X500Name(""), null, "test@example.com");

            Files.write(Paths.get(nameDER), testCertificate.getEncoded());

            System.out.println(String.format("openssl x509 -inform DER -outform PEM -in %s -out %s -text", nameDER, namePEM));
        }

    }

    private static X509Certificate createTestCertificate(PrivateKey caPrivateKey, X500Name issuerDN, X500Name subjectDN, String username,
            String smtpUTF8Mailbox) throws Exception {

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

        //SPONSOR_VALIDATED_MULTIPURPOSE
        final String mailboxValidatedMultipurposeOID = "2.23.140.1.5.3.2";
        Extension certificatePolicies = getCertificatePolicies(mailboxValidatedMultipurposeOID);

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(issuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN, subjectPublicKeyInfo);
        certificateBuilder.addExtension(certificatePolicies);

        if (username != null) {
            GeneralName generalName = new GeneralName(GeneralName.rfc822Name, String.format("%s@example.com", username));
            GeneralNames generalNames = new GeneralNames(generalName);
            byte[] encoded = generalNames.toASN1Primitive().getEncoded(ASN1Encoding.DER);
            Extension san = new Extension(Extension.subjectAlternativeName, subjectDN.size() == 0, encoded);
            certificateBuilder.addExtension(san);
        }

        if (smtpUTF8Mailbox != null) {
            //id-pkix
            //FROM PKIX1Explicit-2009
            //{ iso(1) identified-organization(3) dod(6) internet(1) security(5)
            //    mechanisms(5) pkix(7) id-mod(0) id-mod-pkix1-explicit-02(51) } ;
            //
            //id-on OBJECT IDENTIFIER ::= { id-pkix 8 }
            //id-on-SmtpUTF8Mailbox OBJECT IDENTIFIER ::= { id-on 9 }

            ASN1EncodableVector otherNameVector = new ASN1EncodableVector();
            otherNameVector.add(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.8.9"));
            otherNameVector.add(new DERTaggedObject(true, 0, new DERUTF8String(smtpUTF8Mailbox)));
            ASN1Sequence otherName = new DERSequence(otherNameVector);

            GeneralName generalName = new GeneralName(GeneralName.otherName, otherName);

            List<GeneralName> generalNames = Collections.singletonList(generalName);
            GeneralName[] generalNameArray = generalNames.toArray(new GeneralName[0]);
            GeneralNames subjectAlternativeName = new GeneralNames(generalNameArray);
            byte[] encodedSAN = subjectAlternativeName.getEncoded(ASN1Encoding.DER);
            certificateBuilder.addExtension(Extension.subjectAlternativeName, subjectDN.size() == 0, encodedSAN);

        }

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

