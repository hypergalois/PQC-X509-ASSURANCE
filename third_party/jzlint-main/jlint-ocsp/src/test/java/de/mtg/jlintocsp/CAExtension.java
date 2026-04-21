package de.mtg.jlintocsp;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.CertStatus;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.ocsp.ResponderID;
import org.bouncycastle.asn1.ocsp.ResponseBytes;
import org.bouncycastle.asn1.ocsp.ResponseData;
import org.bouncycastle.asn1.ocsp.SingleResponse;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import de.mtg.jzlint.LintResult;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class CAExtension implements BeforeAllCallback, BeforeEachCallback {

    public static final String SHA_256_WITH_RSA_ENCRYPTION = "sha256WithRSAEncryption";

    private X509Certificate caCertificate;
    private X500Name caIssuerDN;
    private SubjectPublicKeyInfo subjectPublicKeyInfo;
    private PrivateKey privateKey;
    private byte[] standardOCSPResponse;

    @Override
    public void beforeAll(ExtensionContext extensionContext) throws Exception {

        Security.addProvider(new BouncyCastleProvider());

        this.caIssuerDN = new X500Name("CN=Lint CA, O=Lint, C=DE");
        X500Name caSubjectDN = caIssuerDN;

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(2048);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        this.subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        BigInteger serialNumber = new BigInteger(96, new Random());
        Date notBefore = Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
        Date noteAfter = Date.from(LocalDateTime.now().plusYears(5).atZone(ZoneId.systemDefault()).toInstant());

        X509v3CertificateBuilder certBuild = new X509v3CertificateBuilder(caIssuerDN, serialNumber, notBefore, noteAfter, caSubjectDN, subjectPublicKeyInfo);

        AuthorityKeyIdentifier aki = new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(publicKey);
        SubjectKeyIdentifier ski = new JcaX509ExtensionUtils().createSubjectKeyIdentifier(publicKey);

        Extension akie = new Extension(Extension.authorityKeyIdentifier, false, aki.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        Extension skie = new Extension(Extension.subjectKeyIdentifier, false, ski.toASN1Primitive().getEncoded(ASN1Encoding.DER));

        certBuild.addExtension(akie);
        certBuild.addExtension(skie);

        ContentSigner contentSigner = new JcaContentSignerBuilder(SHA_256_WITH_RSA_ENCRYPTION).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(privateKey);
        X509CertificateHolder x509CertificateHolder = certBuild.build(contentSigner);

        this.caCertificate = new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(x509CertificateHolder);
        this.standardOCSPResponse = createOCSPResponse(OCSPResponseStatus.SUCCESSFUL);

    }

    public byte[] createOCSPResponse(int responseStatus) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException {

        ASN1ObjectIdentifier sha256 = NISTObjectIdentifiers.id_sha256;
        AlgorithmIdentifier aid = new AlgorithmIdentifier(sha256, DERNull.INSTANCE);

        MessageDigest messageDigest = MessageDigest.getInstance(sha256.getId(), BouncyCastleProvider.PROVIDER_NAME);
        messageDigest.reset();
        byte[] issuerDNHash = messageDigest.digest(caIssuerDN.getEncoded(ASN1Encoding.DER));
        messageDigest.reset();
        byte[] issuerPKHash = messageDigest.digest(subjectPublicKeyInfo.getPublicKeyData().getBytes());

        CertID certID = new CertID(aid, new DEROctetString(issuerDNHash), new DEROctetString(issuerPKHash), new ASN1Integer(caCertificate.getSerialNumber()));
        CertStatus certStatus = new CertStatus();
        long epochNow = System.currentTimeMillis();
        ASN1GeneralizedTime thisUpdate = new ASN1GeneralizedTime(new Date(epochNow));
        ASN1GeneralizedTime nextUpdate = new ASN1GeneralizedTime(new Date(epochNow + 86400 * 1000));
        SingleResponse singleResponse = new SingleResponse(certID, certStatus, thisUpdate, nextUpdate, (Extensions) null);

        ResponderID responderID = new ResponderID(caIssuerDN);
        ASN1GeneralizedTime producedAt = new ASN1GeneralizedTime(new Date(epochNow));
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(singleResponse);
        ResponseData responseData = new ResponseData(new ASN1Integer(0L), responderID, producedAt, new DERSequence(vector), null);

        AlgorithmIdentifier signatureAID = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);

        Signature jcaSignature = Signature.getInstance(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), BouncyCastleProvider.PROVIDER_NAME);
        jcaSignature.initSign(privateKey);
        jcaSignature.update(responseData.getEncoded(ASN1Encoding.DER));
        byte[] signature = jcaSignature.sign();
        BasicOCSPResponse basicOCSPResponse = new BasicOCSPResponse(responseData, signatureAID, new DERBitString(signature), null);

        ResponseBytes responseBytes = new ResponseBytes(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.1"), new DEROctetString(basicOCSPResponse.getEncoded(ASN1Encoding.DER)));

        OCSPResponse ocspResponse = new OCSPResponse(new OCSPResponseStatus(responseStatus), responseBytes);

        return ocspResponse.getEncoded(ASN1Encoding.DER);
    }

    public byte[] getCorrectResponse() {
        return this.standardOCSPResponse;
    }

    public X509Certificate getCaCertificate() {
        return this.caCertificate;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return subjectPublicKeyInfo;
    }

    public X500Name getCaIssuerDN() {
        return caIssuerDN;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public void beforeEach(ExtensionContext extensionContext) throws Exception {

    }

    public void assertLintResult(LintResult expectedResult, boolean expectedCheckApplies, JavaOCSPResponseLint lint, byte[] ocspResponse) {
        assertEquals(expectedCheckApplies, lint.checkApplies(ocspResponse));
        if (expectedCheckApplies) {
            assertEquals(expectedResult.getStatus(), lint.execute(ocspResponse).getStatus());
            assertEquals(expectedResult.getDetails(), lint.execute(ocspResponse).getDetails());
        }

    }

}