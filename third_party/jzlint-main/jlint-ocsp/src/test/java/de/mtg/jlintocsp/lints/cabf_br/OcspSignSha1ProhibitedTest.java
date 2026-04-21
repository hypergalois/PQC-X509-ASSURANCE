package de.mtg.jlintocsp.lints.cabf_br;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Date;

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
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import de.mtg.jlintocsp.CAExtension;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Status;

class OcspSignSha1ProhibitedTest {
    @RegisterExtension
    static CAExtension caExtension = new CAExtension();

    @Test
    void passTest() {
        byte[] correctResponse = caExtension.getCorrectResponse();
        caExtension.assertLintResult(LintResult.of(Status.PASS), true, new OcspSignSha1Prohibited(), correctResponse);
    }

    @Test
    void errorTest() throws NoSuchAlgorithmException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException {
        byte[] response = createWrongOCSPResponse();
        caExtension.assertLintResult(LintResult.of(Status.ERROR, String.format("Disallowed signature algorithm %s in OCSP response.", PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())), true, new OcspSignSha1Prohibited(), response);
    }

    public byte[] createWrongOCSPResponse() throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException, SignatureException {

        ASN1ObjectIdentifier sha256 = NISTObjectIdentifiers.id_sha256;
        AlgorithmIdentifier aid = new AlgorithmIdentifier(sha256, DERNull.INSTANCE);

        MessageDigest messageDigest = MessageDigest.getInstance(sha256.getId(), BouncyCastleProvider.PROVIDER_NAME);
        messageDigest.reset();
        byte[] issuerDNHash = messageDigest.digest(caExtension.getCaCertificate().getIssuerX500Principal().getEncoded());
        messageDigest.reset();
        byte[] issuerPKHash = messageDigest.digest(caExtension.getSubjectPublicKeyInfo().getPublicKeyData().getBytes());

        CertID certID = new CertID(aid, new DEROctetString(issuerDNHash), new DEROctetString(issuerPKHash), new ASN1Integer(caExtension.getCaCertificate().getSerialNumber()));
        CertStatus certStatus = new CertStatus();
        long epochNow = System.currentTimeMillis();
        ASN1GeneralizedTime thisUpdate = new ASN1GeneralizedTime(new Date(epochNow));
        ASN1GeneralizedTime nextUpdate = new ASN1GeneralizedTime(new Date(epochNow + 86400 * 1000));
        SingleResponse singleResponse = new SingleResponse(certID, certStatus, thisUpdate, nextUpdate, (Extensions) null);

        ResponderID responderID = new ResponderID(caExtension.getCaIssuerDN());
        ASN1GeneralizedTime producedAt = new ASN1GeneralizedTime(new Date(epochNow));
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(singleResponse);
        ResponseData responseData = new ResponseData(new ASN1Integer(0L), responderID, producedAt, new DERSequence(vector), null);

        AlgorithmIdentifier signatureAID = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE);

        Signature jcaSignature = Signature.getInstance(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), BouncyCastleProvider.PROVIDER_NAME);
        jcaSignature.initSign(caExtension.getPrivateKey());
        jcaSignature.update(responseData.getEncoded(ASN1Encoding.DER));
        byte[] signature = jcaSignature.sign();
        BasicOCSPResponse basicOCSPResponse = new BasicOCSPResponse(responseData, signatureAID, new DERBitString(signature), null);

        ResponseBytes responseBytes = new ResponseBytes(new ASN1ObjectIdentifier("1.3.6.1.5.5.7.48.1.1"), new DEROctetString(basicOCSPResponse.getEncoded(ASN1Encoding.DER)));

        OCSPResponse ocspResponse = new OCSPResponse(new OCSPResponseStatus(0), responseBytes);

        return ocspResponse.getEncoded(ASN1Encoding.DER);
    }

}
