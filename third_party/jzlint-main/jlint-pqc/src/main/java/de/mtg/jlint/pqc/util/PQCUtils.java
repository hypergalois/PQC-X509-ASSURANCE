package de.mtg.jlint.pqc.util;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import de.mtg.jzlint.utils.ASN1CertificateUtils;

public final class PQCUtils {

    public static ASN1ObjectIdentifier ID_ALG_SLH_DSA_128S_SHAKE = NISTObjectIdentifiers.id_slh_dsa_shake_128s;

    public static ASN1ObjectIdentifier ID_ALG_SLH_DSA_128F_SHAKE = NISTObjectIdentifiers.id_slh_dsa_shake_128f;

    public static ASN1ObjectIdentifier ID_ALG_SLH_DSA_192S_SHAKE = NISTObjectIdentifiers.id_slh_dsa_shake_192s;

    public static ASN1ObjectIdentifier ID_ALG_SLH_DSA_192F_SHAKE = NISTObjectIdentifiers.id_slh_dsa_shake_192f;

    public static ASN1ObjectIdentifier ID_ALG_SLH_DSA_256S_SHAKE = NISTObjectIdentifiers.id_slh_dsa_shake_256s;

    public static ASN1ObjectIdentifier ID_ALG_SLH_DSA_256F_SHAKE = NISTObjectIdentifiers.id_slh_dsa_shake_256f;

    public static ASN1ObjectIdentifier ID_ALG_SLH_DSA_128S_SHA2 = NISTObjectIdentifiers.id_slh_dsa_sha2_128s;

    public static ASN1ObjectIdentifier ID_ALG_SLH_DSA_128F_SHA2 = NISTObjectIdentifiers.id_slh_dsa_sha2_128f;

    public static ASN1ObjectIdentifier ID_ALG_SLH_DSA_192S_SHA2 = NISTObjectIdentifiers.id_slh_dsa_sha2_192s;

    public static ASN1ObjectIdentifier ID_ALG_SLH_DSA_192F_SHA2 = NISTObjectIdentifiers.id_slh_dsa_sha2_192f;

    public static ASN1ObjectIdentifier ID_ALG_SLH_DSA_256S_SHA2 = NISTObjectIdentifiers.id_slh_dsa_sha2_256s;

    public static ASN1ObjectIdentifier ID_ALG_SLH_DSA_256F_SHA2 = NISTObjectIdentifiers.id_slh_dsa_sha2_256f;

    public static List<ASN1ObjectIdentifier> ALL_SLHDSA_PUBLIC_KEY_OIDS = Arrays.asList(
            ID_ALG_SLH_DSA_128S_SHAKE,
            ID_ALG_SLH_DSA_128F_SHAKE,
            ID_ALG_SLH_DSA_192S_SHAKE,
            ID_ALG_SLH_DSA_192F_SHAKE,
            ID_ALG_SLH_DSA_256S_SHAKE,
            ID_ALG_SLH_DSA_256F_SHAKE,
            ID_ALG_SLH_DSA_128S_SHA2,
            ID_ALG_SLH_DSA_128F_SHA2,
            ID_ALG_SLH_DSA_192S_SHA2,
            ID_ALG_SLH_DSA_192F_SHA2,
            ID_ALG_SLH_DSA_256S_SHA2,
            ID_ALG_SLH_DSA_256F_SHA2
    );

    public static List<ASN1ObjectIdentifier> ALL_SLHDSA_SIGNATURE_OIDS = Arrays.asList(
            ID_ALG_SLH_DSA_128S_SHAKE,
            ID_ALG_SLH_DSA_128F_SHAKE,
            ID_ALG_SLH_DSA_192S_SHAKE,
            ID_ALG_SLH_DSA_192F_SHAKE,
            ID_ALG_SLH_DSA_256S_SHAKE,
            ID_ALG_SLH_DSA_256F_SHAKE,
            ID_ALG_SLH_DSA_128S_SHA2,
            ID_ALG_SLH_DSA_128F_SHA2,
            ID_ALG_SLH_DSA_192S_SHA2,
            ID_ALG_SLH_DSA_192F_SHA2,
            ID_ALG_SLH_DSA_256S_SHA2,
            ID_ALG_SLH_DSA_256F_SHA2
    );

    public static ASN1ObjectIdentifier ID_ML_DSA_44 = NISTObjectIdentifiers.id_ml_dsa_44;
    public static ASN1ObjectIdentifier ID_ML_DSA_65 = NISTObjectIdentifiers.id_ml_dsa_65;
    public static ASN1ObjectIdentifier ID_ML_DSA_87 = NISTObjectIdentifiers.id_ml_dsa_87;

    public static ASN1ObjectIdentifier ID_ALG_KYBER_512 = NISTObjectIdentifiers.id_alg_ml_kem_512;
    public static ASN1ObjectIdentifier ID_ALG_KYBER_768 = NISTObjectIdentifiers.id_alg_ml_kem_768;
    public static ASN1ObjectIdentifier ID_ALG_KYBER_1024 = NISTObjectIdentifiers.id_alg_ml_kem_1024;

    public static List<ASN1ObjectIdentifier> ALL_MLDSA_PUBLIC_KEY_OIDS = Arrays.asList(
            ID_ML_DSA_44,
            ID_ML_DSA_65,
            ID_ML_DSA_87);
    public static List<ASN1ObjectIdentifier> ALL_MLDSA_SIGNATURE_OIDS = Arrays.asList(
            ID_ML_DSA_44,
            ID_ML_DSA_65,
            ID_ML_DSA_87);

    public static List<ASN1ObjectIdentifier> ALL_MLKEM_PUBLIC_KEY_OIDS = Arrays.asList(
            ID_ALG_KYBER_512,
            ID_ALG_KYBER_768,
            ID_ALG_KYBER_1024);

    private PQCUtils() {
        // empty
    }

    public static boolean isPublicKeyMLDSA(X509Certificate certificate) {
        return isPublicKey(certificate, ALL_MLDSA_PUBLIC_KEY_OIDS);
    }

    public static boolean isPublicKeyMLKEM(X509Certificate certificate) {
        return isPublicKey(certificate, ALL_MLKEM_PUBLIC_KEY_OIDS);
    }

    public static boolean isPublicKeySLHDSA(X509Certificate certificate) {
        return isPublicKey(certificate, ALL_SLHDSA_PUBLIC_KEY_OIDS);
    }

    public static boolean isSignedByMLDSA(X509Certificate certificate) throws CertificateEncodingException, IOException {
        return isSignedBy(certificate, ALL_MLDSA_SIGNATURE_OIDS);
    }

    public static boolean isSignedBySLHDSA(X509Certificate certificate) throws CertificateEncodingException, IOException {
        return isSignedBy(certificate, ALL_SLHDSA_SIGNATURE_OIDS);
    }

    private static boolean isPublicKey(X509Certificate certificate, List<ASN1ObjectIdentifier> publicKeyOIDs) {
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded());
        ASN1ObjectIdentifier publicKeyAlgorithmOID = subjectPublicKeyInfo.getAlgorithm().getAlgorithm();
        Predicate<ASN1ObjectIdentifier> oidMatches = asn1ObjectIdentifier -> asn1ObjectIdentifier.equals(publicKeyAlgorithmOID);
        return publicKeyOIDs.stream().anyMatch(oidMatches);
    }

    private static boolean isSignedBy(X509Certificate certificate, List<ASN1ObjectIdentifier> signatureOIDs)
            throws CertificateEncodingException, IOException {
        ASN1Encodable signatureAlgorithmIdentifier = ASN1CertificateUtils.getInnerSignature(certificate);
        AlgorithmIdentifier algorithmIdentifier =
                AlgorithmIdentifier.getInstance(signatureAlgorithmIdentifier.toASN1Primitive().getEncoded(ASN1Encoding.DER));
        ASN1ObjectIdentifier signatureAlgorithmOID = algorithmIdentifier.getAlgorithm();
        Predicate<ASN1ObjectIdentifier> oidMatches = asn1ObjectIdentifier -> asn1ObjectIdentifier.equals(signatureAlgorithmOID);
        return signatureOIDs.stream().anyMatch(oidMatches);
    }

    public static String toHexDigest(String inputBase64) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA256", BouncyCastleProvider.PROVIDER_NAME);
            return new String(Hex.encode(messageDigest.digest(Base64.decode(inputBase64))));
        } catch (NoSuchAlgorithmException | NoSuchProviderException ex) {
            return inputBase64;
        }
    }

}
