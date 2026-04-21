package de.mtg.jzlint.ca;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
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
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Random;

/**
 * Certificates for lints: new CAB forum validities
 */
public class CreateCertificate015 {

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

        //NB: March 15, 2026 -1 sec, First: NE
        {
            ZonedDateTime notBefore = ZonedDateTime.of(2026, 3, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
            ZonedDateTime notAfter = notBefore.plusYears(1);
            ZonedDateTime notBeforeMinusOne = notBefore.minusSeconds(1);
            String name = "justBeforeFirstMilestone";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBeforeMinusOne, notAfter);
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "NE",
                    "NE - certificate is issued at 20260314 235959, just before the first date");
        }

        //NB: On March 15, 2026, +200 days - 1 second, First PASS
        {
            ZonedDateTime notBefore = ZonedDateTime.of(2026, 3, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
            ZonedDateTime notAfter = notBefore.plusDays(200).minusSeconds(1);
            String name = "exactlyOnFirstMilestoneExactly200days";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBefore, notAfter);
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate is issued at 20260315 000000, exactly on the first date and has the the full 200-day validity");
        }

        //NB: On March 15, 2026, +199 days - 1 second, First PASS
        {
            ZonedDateTime notBefore = ZonedDateTime.of(2026, 3, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
            ZonedDateTime notAfter = notBefore.plusDays(199).minusSeconds(1);
            String name = "exactlyOnFirstMilestoneExactly199days";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBefore, notAfter);
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate is issued at 20260315 000000, exactly on the first date and has a full 199-day validity");
        }

        //NB: On March 15, 2026, +200 days, ERROR
        {
            ZonedDateTime notBefore = ZonedDateTime.of(2026, 3, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
            ZonedDateTime notAfter = notBefore.plusDays(200);
            String name = "exactlyOnFirstMilestoneLongerThan200days";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBefore, notAfter);
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Error",
                    "Error - certificate is issued at 20260315 000000, exactly on the first date and has a full 200-day validity plus one second");
        }

        //NB: March 15, 2027 -1 sec, First: PASS, Second: NE
        {
            ZonedDateTime notBefore = ZonedDateTime.of(2027, 3, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
            ZonedDateTime notBeforeMinusOne = notBefore.minusSeconds(1);
            ZonedDateTime notAfter = notBeforeMinusOne.plusDays(200).minusSeconds(1);
            String name = "justBeforeSecondMilestoneExactly200days";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBeforeMinusOne, notAfter);
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate is issued at 20270314 235959, just before the second date and has a full 200-day validity");
        }


        //NB: On March 15, 2027, +100 days - 1 second, First: NE, Second: PASS
        {
            ZonedDateTime notBefore = ZonedDateTime.of(2027, 3, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
            ZonedDateTime notAfter = notBefore.plusDays(100).minusSeconds(1);
            String name = "exactlyOnSecondMilestoneExactly100days";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBefore, notAfter);
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate is issued at 20270315 000000, exactly on the the second date and has a full 100-day validity");
        }

        //NB: On March 15, 2027, +99 days - 1 second, First: NE, Second: PASS
        {
            ZonedDateTime notBefore = ZonedDateTime.of(2027, 3, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
            ZonedDateTime notAfter = notBefore.plusDays(99).minusSeconds(1);
            String name = "exactlyOnSecondMilestoneExactly99days";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBefore, notAfter);
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate is issued at 20270315 000000, exactly on the second date and has a full 99-day validity");
        }

        //NB: On March 15, 2027, +100 days, ERROR
        {
            ZonedDateTime notBefore = ZonedDateTime.of(2027, 3, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
            ZonedDateTime notAfter = notBefore.plusDays(100);
            String name = "exactlyOnSecondMilestoneLongerThan100days";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBefore, notAfter);
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Error",
                    "Error - certificate is issued at 20270315 000000, exactly on the second date and has a full 100-day validity plus one second");
        }

        //NB: March 15, 2029 -1 sec, Second: PASS, Third: NE
        {
            ZonedDateTime notBefore = ZonedDateTime.of(2029, 3, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
            ZonedDateTime notBeforeMinusOne = notBefore.minusSeconds(1);
            ZonedDateTime notAfter = notBeforeMinusOne.plusDays(100).minusSeconds(1);
            String name = "justBeforeThirdMilestoneExactly100days";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBeforeMinusOne, notAfter);
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "NE",
                    "NE - certificate is issued at 20290314 235959, just before the third date and has a full 100-day validity");
        }

        //NB: On March 15, 2029, +47 days - 1 second, Second:, NE, Third: PASS
        {
            ZonedDateTime notBefore = ZonedDateTime.of(2029, 3, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
            ZonedDateTime notAfter = notBefore.plusDays(47).minusSeconds(1);
            String name = "exactlyOnThirdMilestoneExactly47days";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBefore, notAfter);
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate is issued at 20290315 000000, exactly on the third date and has a full 47-day validity");
        }

        //NB: On March 15, 2029, +46 days - 1 second, Second:, NE, Third: PASS
        {
            ZonedDateTime notBefore = ZonedDateTime.of(2029, 3, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
            ZonedDateTime notAfter = notBefore.plusDays(46).minusSeconds(1);
            String name = "exactlyOnThirdMilestoneExactly46days";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBefore, notAfter);
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate is issued at 20290315 000000, exactly on the third date and has a full 46-day validity");
        }

        //NB: On March 15, 2029, +47 days, Third: Error
        {
            ZonedDateTime notBefore = ZonedDateTime.of(2029, 3, 15, 0, 0, 0, 0, ZoneId.of("UTC"));
            ZonedDateTime notAfter = notBefore.plusDays(47);
            String name = "exactlyOnThirdMilestoneLongerThan47days";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBefore, notAfter);
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate is issued at 20290315 000000, exactly on the third date and has a full 47-day validity plus one second");
        }

        //NB: On February 01, 2032, +47 days -1 , Third: Pass
        {
            ZonedDateTime notBefore = ZonedDateTime.of(2032, 2, 1, 0, 0, 0, 0, ZoneId.of("UTC"));
            ZonedDateTime notAfter = ZonedDateTime.of(2032, 3, 18, 23, 59, 59, 0, ZoneId.of("UTC"));
            String name = "withinThirdMilestoneLeapYear";
            String nameDER = String.format("%s.der", name);
            String namePEM = String.format("%s.pem", name);
            X509Certificate testCertificate = createTestCertificate(privateKey, caIssuerDN, notBefore, notAfter);
            Utils.handleIssuedCertificate(args, nameDER, testCertificate, namePEM, zlintTestVectors, "Pass",
                    "Pass - certificate is issued at 20320201 000000, considering the leap year and has a full 47-day validity");
        }

        System.out.println(zlintTestVectors);

    }

    private static X509Certificate createTestCertificate(PrivateKey caPrivateKey, X500Name issuerDN, ZonedDateTime notBefore, ZonedDateTime notAfter)
            throws Exception {

        BigInteger serialNumber = new BigInteger(96, new Random());

        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notAfter.toInstant());

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
