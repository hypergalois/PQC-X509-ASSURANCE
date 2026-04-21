package de.mtg.jlint.smpki;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import de.mtg.jzlint.JavaCRLLint;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.LintJSONResult;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Runner;
import de.mtg.jzlint.Status;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CAExtension implements BeforeAllCallback {

    public static final String SHA_256_WITH_RSA_ENCRYPTION = "sha256WithRSAEncryption";

    private X509Certificate caCertificate;
    private X500Name caIssuerDN;
    private SubjectPublicKeyInfo subjectPublicKeyInfo;
    private PrivateKey caPrivateKey;

    private PublicKey caPublicKey;

    @Override
    public void beforeAll(ExtensionContext extensionContext) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        this.caIssuerDN = new X500Name("CN=Lint CA, O=Lint, C=DE");
        X500Name caSubjectDN = caIssuerDN;

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.caPrivateKey = keyPair.getPrivate();
        this.caPublicKey = keyPair.getPublic();

        this.subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(caPublicKey.getEncoded());
        BigInteger serialNumber = new BigInteger(96, new Random());
        Date notBefore = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        Date noteAfter = Date.from(LocalDateTime.now().plusYears(5).atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(caIssuerDN, serialNumber, notBefore, noteAfter, caSubjectDN, subjectPublicKeyInfo);

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey);
        SubjectKeyIdentifier ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(caPublicKey);

        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension skie = new Extension(Extension.subjectKeyIdentifier, false, ski.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        BasicConstraints bc = new BasicConstraints(true);
        Extension basicConstraints = new Extension(Extension.basicConstraints, true, bc.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        certificateBuilder.addExtension(akie);
        certificateBuilder.addExtension(skie);
        certificateBuilder.addExtension(basicConstraints);

        ContentSigner contentSigner =
                new JcaContentSignerBuilder(SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        this.caCertificate = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

    }

    public X509Certificate getCaCertificate() {
        return this.caCertificate;
    }

    public X500Name getIsserDN() {
        return this.caIssuerDN;
    }

    public PrivateKey getCaPrivateKey() {
        return this.caPrivateKey;
    }

    public PublicKey getCaPublicKey() {
        return this.caPublicKey;
    }


    public X509Certificate createEnduserCertificate(String subjectDN)
            throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, NoSuchProviderException {

        BigInteger serialNumber = new BigInteger(96, new Random());
        ZonedDateTime notBefore = ZonedDateTime.of(2025, 7, 1, 0, 0, 0, 0, ZoneId.of("UTC"));
        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        X500Name certificateSubjectDN = new X500Name(subjectDN);

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey);
        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        SubjectKeyIdentifier ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
        Extension skie = new Extension(Extension.subjectKeyIdentifier, false, ski.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.digitalSignature);
        Extension ku = new Extension(Extension.keyUsage, true, keyUsage.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth);
        Extension eku = new Extension(Extension.extendedKeyUsage, true, extendedKeyUsage.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        BasicConstraints bc = new BasicConstraints(false);
        Extension basicConstraints = new Extension(Extension.basicConstraints, true, bc.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        GeneralName generalName = new GeneralName(GeneralName.rfc822Name, String.format("test@example.com"));
        GeneralNames generalNames = new GeneralNames(generalName);
        byte[] encoded = generalNames.toASN1Primitive().getEncoded(ASN1Encoding.DER);
        Extension ian = new Extension(Extension.issuerAlternativeName, false, encoded);
        Extension san = new Extension(Extension.subjectAlternativeName, false, encoded);

        DERIA5String url = new DERIA5String("https://crldp.example.com/crl");
        GeneralName[] generalNameArray = new GeneralName[1];
        generalNameArray[0] = new GeneralName(6, url);
        GeneralNames crldpGeneralNames = new GeneralNames(generalNameArray);
        DistributionPointName distributionPointName = new DistributionPointName(crldpGeneralNames);
        DistributionPoint[] distributionPoints = new DistributionPoint[1];
        distributionPoints[0] = new DistributionPoint(distributionPointName, null, null);
        CRLDistPoint crlDistributionPoint = new CRLDistPoint(distributionPoints);
        Extension crldp = new Extension(Extension.cRLDistributionPoints, false, crlDistributionPoint.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        Extension certificatePolicies = getCertificatePolicies("0.4.0.127.0.7.3.4.1.1.1");

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(caIssuerDN, serialNumber, notBeforeDate, noteAfterDate, certificateSubjectDN, subjectPublicKeyInfo);
        certificateBuilder.addExtension(akie);
        certificateBuilder.addExtension(skie);
        certificateBuilder.addExtension(ku);
        certificateBuilder.addExtension(eku);
        certificateBuilder.addExtension(basicConstraints);
        certificateBuilder.addExtension(ian);
        certificateBuilder.addExtension(san);
        certificateBuilder.addExtension(crldp);
        certificateBuilder.addExtension(certificatePolicies);
        var contentSigner =
                new JcaContentSignerBuilder(SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        var x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

    }

    public X509Certificate createEMTCertificate()
            throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, NoSuchProviderException {

        BigInteger serialNumber = new BigInteger(96, new Random());
        ZonedDateTime notBefore = ZonedDateTime.of(2025, 7, 1, 0, 0, 0, 0, ZoneId.of("UTC"));
        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        X500Name subjectDN = new X500Name("CN=ORG.EMT.EXT, O=SM-PKI-DE, SERIALNUMBER=1, C=DE");

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey);
        SubjectKeyIdentifier ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension skie = new Extension(Extension.subjectKeyIdentifier, false, ski.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        X509v3CertificateBuilder certificateBuilder =
                new X509v3CertificateBuilder(caIssuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN, subjectPublicKeyInfo);
        certificateBuilder.addExtension(akie);
        certificateBuilder.addExtension(skie);
        ContentSigner contentSigner =
                new JcaContentSignerBuilder(SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

    }

    public void assertLintResult(LintResult expectedResult, JavaLint lint, X509Certificate certificate, boolean expectedCheckApplies,
            String expectedMessage) throws Exception {
        assertEquals(expectedCheckApplies, lint.checkApplies(certificate));

        LintResult lintResult = null;
        if (expectedCheckApplies) {
            lintResult = lint.execute(certificate);
            assertEquals(expectedResult.getStatus().name().toUpperCase(Locale.ROOT), lintResult.getStatus().toString(), lintResult.getDetails());
        }

        if (expectedMessage != null && !expectedMessage.isEmpty() && lintResult != null) {
            assertEquals(expectedMessage, lintResult.getDetails());
        }
    }

    public void assertLintResult(LintResult expectedResult, boolean expectedCheckApplies, JavaCRLLint lint, X509CRL crl, String expectedMessage) {
        assertEquals(expectedCheckApplies, lint.checkApplies(crl));
        if (expectedResult.getStatus() != Status.NA) {
            assertEquals(expectedResult.getStatus(), lint.execute(crl).getStatus(), "");
        }
        if (expectedMessage != null && !expectedMessage.isEmpty()) {
            assertEquals(expectedMessage, lint.execute(crl).getDetails());
        }
    }

    private static Optional<Extension> getCertificatePolicies(List<String> oids) throws IOException {

        if (oids == null || oids.isEmpty()) {
            return Optional.empty();
        }

        PolicyInformation[] policies = new PolicyInformation[oids.size()];
        List<PolicyInformation> policiesList = new ArrayList<>();

        for (String oid : oids) {
            PolicyInformation policyInformation = new PolicyInformation(new ASN1ObjectIdentifier(oid));
            policiesList.add(policyInformation);
        }

        CertificatePolicies cps = new CertificatePolicies(policiesList.toArray(policies));
        return Optional.of(new Extension(Extension.certificatePolicies, false, cps.toASN1Primitive().getEncoded(ASN1Encoding.DER)));

    }

    public static Extension getCertificatePolicies(String policyOID) throws IOException {
        PolicyInformation[] policies = new PolicyInformation[1];
        List<PolicyInformation> policiesList = new ArrayList<>();
        PolicyInformation policyInformation = new PolicyInformation(new ASN1ObjectIdentifier(policyOID));
        policiesList.add(policyInformation);
        CertificatePolicies cps = new CertificatePolicies(policiesList.toArray(policies));
        return new Extension(Extension.certificatePolicies, false, cps.toASN1Primitive().getEncoded(ASN1Encoding.DER));
    }

}
