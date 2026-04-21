package de.mtg.jlint.lints;

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
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
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

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(caIssuerDN, serialNumber, notBefore, noteAfter, caSubjectDN, subjectPublicKeyInfo);

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey);
        SubjectKeyIdentifier ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(caPublicKey);

        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension skie = new Extension(Extension.subjectKeyIdentifier, false, ski.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        BasicConstraints bc = new BasicConstraints(true);
        Extension basicConstraints = new Extension(Extension.basicConstraints, true, bc.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        certificateBuilder.addExtension(akie);
        certificateBuilder.addExtension(skie);
        certificateBuilder.addExtension(basicConstraints);

        ContentSigner contentSigner = new JcaContentSignerBuilder(SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
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

    public X509Certificate createSMimeEECertificate() throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeyException {

        BigInteger serialNumber = new BigInteger(96, new Random());
        ZonedDateTime notBefore = ZonedDateTime.of(2023, 9, 1, 0, 0, 0, 0, ZoneId.of("UTC"));
        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        X500Name subjectDN = new X500Name("CN=Certificate, O=Lint, C=DE");

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey);
        SubjectKeyIdentifier ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension skie = new Extension(Extension.subjectKeyIdentifier, false, ski.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection);

        Extension eku = new Extension(Extension.extendedKeyUsage, false, extendedKeyUsage.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Optional<Extension> certificatePolicies = getCertificatePolicies(Arrays.asList("2.23.140.1.5.1.3"));
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(caIssuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN, subjectPublicKeyInfo);
        certificateBuilder.addExtension(akie);
        certificateBuilder.addExtension(skie);
        certificateBuilder.addExtension(eku);
        certificateBuilder.addExtension(certificatePolicies.get());
        ContentSigner contentSigner = new JcaContentSignerBuilder(SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

    }

    public X509Certificate createCodeSigningEECertificate() throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeyException {

        BigInteger serialNumber = new BigInteger(96, new Random());
        ZonedDateTime notBefore = ZonedDateTime.of(2023, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"));
        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        X500Name subjectDN = new X500Name("CN=Certificate, O=Lint, C=DE");

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey);
        SubjectKeyIdentifier ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension skie = new Extension(Extension.subjectKeyIdentifier, false, ski.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_codeSigning);

        Extension eku = new Extension(Extension.extendedKeyUsage, false, extendedKeyUsage.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(caIssuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN, subjectPublicKeyInfo);
        certificateBuilder.addExtension(akie);
        certificateBuilder.addExtension(skie);
        certificateBuilder.addExtension(eku);
        ContentSigner contentSigner = new JcaContentSignerBuilder(SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

    }

    public X509Certificate createTimestampingEECertificate() throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeyException {

        BigInteger serialNumber = new BigInteger(96, new Random());
        ZonedDateTime notBefore = ZonedDateTime.of(2023, 1, 1, 0, 0, 0, 0, ZoneId.of("UTC"));
        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        X500Name subjectDN = new X500Name("CN=Certificate, O=Lint, C=DE");

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey);
        SubjectKeyIdentifier ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension skie = new Extension(Extension.subjectKeyIdentifier, false, ski.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping);

        Extension eku = new Extension(Extension.extendedKeyUsage, false, extendedKeyUsage.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(caIssuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN, subjectPublicKeyInfo);
        certificateBuilder.addExtension(akie);
        certificateBuilder.addExtension(skie);
        certificateBuilder.addExtension(eku);
        ContentSigner contentSigner = new JcaContentSignerBuilder(SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

    }

    public X509Certificate createNotEffectiveSmimeCertificate() throws NoSuchAlgorithmException, IOException, OperatorCreationException, CertificateException, NoSuchProviderException, SignatureException, InvalidKeyException {

        BigInteger serialNumber = new BigInteger(96, new Random());

        ZonedDateTime notBefore = ZonedDateTime.of(2023, 8, 31, 23, 59, 59, 0, ZoneId.of("UTC"));
        Date notBeforeDate = Date.from(notBefore.toInstant());
        Date noteAfterDate = Date.from(notBefore.plusYears(1).toInstant());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());

        X500Name subjectDN = new X500Name("CN=Certificate, O=Lint, C=DE");

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey);
        SubjectKeyIdentifier ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);
        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension skie = new Extension(Extension.subjectKeyIdentifier, false, ski.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(KeyPurposeId.id_kp_emailProtection);
        Extension eku = new Extension(Extension.extendedKeyUsage, false, extendedKeyUsage.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(caIssuerDN, serialNumber, notBeforeDate, noteAfterDate, subjectDN, subjectPublicKeyInfo);
        certificateBuilder.addExtension(akie);
        certificateBuilder.addExtension(skie);
        certificateBuilder.addExtension(eku);
        certificateBuilder.addExtension(getCertificatePolicies("2.23.140.1.5.1.2"));
        ContentSigner contentSigner = new JcaContentSignerBuilder(SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CertificateHolder x509CertificateHolder = certificateBuilder.build(contentSigner);

        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);

    }

    public X509CRL createCRL() throws NoSuchAlgorithmException, IOException, OperatorCreationException, CRLException {

        Date thisUpdate = Date.from(LocalDateTime.now().minusHours(1).atZone(ZoneId.systemDefault()).toInstant());
        Date nextUpdate = Date.from(LocalDateTime.now().plusDays(1).atZone(ZoneId.systemDefault()).toInstant());

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(caPublicKey);
        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension crlNumber = new Extension(Extension.cRLNumber, false, new ASN1Integer(1).getEncoded(ASN1Encoding.DER));

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(caIssuerDN, thisUpdate);
        crlBuilder.setNextUpdate(nextUpdate);
        crlBuilder.addExtension(akie);
        crlBuilder.addExtension(crlNumber);
        ContentSigner contentSigner = new JcaContentSignerBuilder(SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);
        X509CRLHolder holder = crlBuilder.build(contentSigner);

        return new JcaX509CRLConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCRL(holder);

    }

    public void assertLintResult(LintResult expectedResult, JavaLint lint, X509Certificate certificate) throws Exception {
        Runner runner = new Runner();
        LintJSONResult lintResult = runner.lintForClassName(certificate, lint.getClass().getCanonicalName());
        assertEquals(expectedResult.getStatus().name().toLowerCase(Locale.ROOT), lintResult.getResult());
    }

    public void assertLintResult(LintResult expectedResult, boolean expectedCheckApplies, JavaCRLLint lint, X509CRL crl, String expectedMessage) {
        assertEquals(expectedCheckApplies, lint.checkApplies(crl));
        if (expectedResult.getStatus() != Status.NA) {
            assertEquals(expectedResult.getStatus(), lint.execute(crl).getStatus());
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
