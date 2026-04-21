package de.mtg.jzlint.ca;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CreateCertificate006 {

    public static final String SUB_SUBJECT_DN = "CN=JLint Sub CA";
    public static final String ROOT_SUBJECT_DN = "CN=JLint Root CA";
    public static final String SHA_256_WITH_RSA = "SHA256withRSA";

    public static final JcaContentSignerBuilder JCA_CONTENT_SIGNER_BUILDER = new JcaContentSignerBuilder(SHA_256_WITH_RSA).setProvider(BouncyCastleProvider.PROVIDER_NAME);
    public static final JcaX509CertificateConverter JCA_X_509_CERTIFICATE_CONVERTER = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);
    public static final String DATE_FORMAT = "yyyy-MM-dd";

    public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, IOException, CertificateException, OperatorCreationException, ParseException {

        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        PublicKey rootPublicKey = rootKeyPair.getPublic();
        PrivateKey rootPrivateKey = rootKeyPair.getPrivate();
        KeyPair subKeyPair = keyPairGenerator.generateKeyPair();
        KeyPair eeKeyPair = keyPairGenerator.generateKeyPair();

        X509Certificate rootCertificate = createRootCertificate(rootPublicKey, rootPrivateKey);

        createCertificates("e_issuer_lint_key_identifier_mismatch", rootKeyPair, subKeyPair, eeKeyPair, rootCertificate);

    }

    //e_issuer_lint_key_identifier_mismatch
    private static void createCertificates(String lintName, KeyPair rootKeyPair, KeyPair subKeyPair, KeyPair eeKeyPair, X509Certificate rootCertificate) throws ParseException, OperatorCreationException, CertificateException, NoSuchAlgorithmException, IOException {

        SubjectPublicKeyInfo subSPKI = SubjectPublicKeyInfo.getInstance(subKeyPair.getPublic().getEncoded());
        X509Certificate subCertificate = getSubCertificate(rootKeyPair, subSPKI, rootCertificate);

        JcaX509ExtensionUtils util = new JcaX509ExtensionUtils();
        AuthorityKeyIdentifier correctAkie = util.createAuthorityKeyIdentifier(subSPKI);

        SubjectPublicKeyInfo eeSPKI = SubjectPublicKeyInfo.getInstance(eeKeyPair.getPublic().getEncoded());
        AuthorityKeyIdentifier wrongAkie = util.createAuthorityKeyIdentifier(eeSPKI);

        X509Certificate naCertificate = createEECertificate(subKeyPair, eeKeyPair, subCertificate, null);
        X509Certificate passCertificate = createEECertificate(subKeyPair, eeKeyPair, subCertificate, correctAkie);
        X509Certificate errorCertificate = createEECertificate(subKeyPair, eeKeyPair, subCertificate, wrongAkie);

        Files.write(Paths.get("na.crt"), naCertificate.getEncoded());
        Files.write(Paths.get("pass.crt"), passCertificate.getEncoded());
        Files.write(Paths.get("error.crt"), errorCertificate.getEncoded());
    }


    private static X509Certificate createRootCertificate(PublicKey rootPublicKey, PrivateKey rootPrivateKey) throws ParseException, OperatorCreationException, CertificateException {
        X500Name rootIssuer = new X500Name(ROOT_SUBJECT_DN);
        X500Name rootSubject = rootIssuer;
        SubjectPublicKeyInfo rootSPKI = SubjectPublicKeyInfo.getInstance(rootPublicKey.getEncoded());
        BigInteger rootSN = new BigInteger("123");
        Date rootNotBefore = new SimpleDateFormat(DATE_FORMAT).parse("2022-01-01");
        Date rootNotAfter = new SimpleDateFormat(DATE_FORMAT).parse("2042-01-01");

        ContentSigner contentSigner = JCA_CONTENT_SIGNER_BUILDER.build(rootPrivateKey);
        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(rootIssuer, rootSN, rootNotBefore, rootNotAfter, rootSubject, rootSPKI);
        X509CertificateHolder certificateHolder = certificateGenerator.build(contentSigner);
        return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(certificateHolder);
    }

    private static X509Certificate getSubCertificate(KeyPair rootKeyPair, SubjectPublicKeyInfo subSPKI, X509Certificate rootCertificate) throws OperatorCreationException, CertificateException, ParseException {
        X500Name subIssuer = X500Name.getInstance(rootCertificate.getSubjectX500Principal().getEncoded());
        X500Name subSubject = new X500Name(SUB_SUBJECT_DN);
        BigInteger subSN = new BigInteger("456");
        Date subNotBefore = new SimpleDateFormat(DATE_FORMAT).parse("2023-01-01");
        Date subNotAfter = new SimpleDateFormat(DATE_FORMAT).parse("2032-01-01");

        ContentSigner contentSigner = JCA_CONTENT_SIGNER_BUILDER.build(rootKeyPair.getPrivate());
        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(subIssuer, subSN, subNotBefore, subNotAfter, subSubject, subSPKI);
        X509CertificateHolder certificateHolder = certificateGenerator.build(contentSigner);
        return JCA_X_509_CERTIFICATE_CONVERTER.getCertificate(certificateHolder);
    }

    private static X509Certificate createEECertificate(KeyPair subKeyPair, KeyPair eeKeyPair, X509Certificate subCertificate, AuthorityKeyIdentifier akie) throws ParseException, OperatorCreationException, CertificateException, IOException {
        X500Name eeIssuer = X500Name.getInstance(subCertificate.getSubjectX500Principal().getEncoded());
        X500Name eeSubject = new X500Name(SUB_SUBJECT_DN);
        SubjectPublicKeyInfo eeSPKI = SubjectPublicKeyInfo.getInstance(eeKeyPair.getPublic().getEncoded());
        BigInteger eeSN = new BigInteger("789");
        Date eeNotBefore = new SimpleDateFormat(DATE_FORMAT).parse("2023-01-02");
        Date eeNotAfter = new SimpleDateFormat(DATE_FORMAT).parse("2024-01-01");

        ContentSigner contentSigner = JCA_CONTENT_SIGNER_BUILDER.build(subKeyPair.getPrivate());
        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(eeIssuer, eeSN, eeNotBefore, eeNotAfter, eeSubject, eeSPKI);
        if (akie != null) {
            certificateGenerator.addExtension(Extension.create(Extension.authorityKeyIdentifier, false, akie));
        }
        X509CertificateHolder certificateHolder = certificateGenerator.build(contentSigner);

        return JCA_X_509_CERTIFICATE_CONVERTER.getCertificate(certificateHolder);
    }

}
