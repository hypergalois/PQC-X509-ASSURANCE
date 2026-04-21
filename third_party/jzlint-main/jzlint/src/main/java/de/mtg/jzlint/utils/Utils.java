package de.mtg.jzlint.utils;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import inet.ipaddr.IPAddressNetwork;
import org.bouncycastle.asn1.ASN1BMPString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.ASN1VisibleString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Utils {

    public static final BigDecimal TWO = new BigDecimal("2");
    public static final String ADOBE_TIMESTAMP_OID = "1.2.840.113583.1.1.9.1";
    public static final String ADOBE_ARCHIVE_REV_INFO_OID = "1.2.840.113583.1.1.9.2";

    private Utils() {
        // empty
    }

    public static boolean hasExtensions(X509Certificate certificate) {
        return !((certificate.getCriticalExtensionOIDs() == null || certificate.getCriticalExtensionOIDs().isEmpty()) &&
                (certificate.getNonCriticalExtensionOIDs() == null || certificate.getNonCriticalExtensionOIDs().isEmpty()));
    }

    public static boolean isCA(X509Certificate certificate) {

        byte[] rawBasicConstraints = certificate.getExtensionValue(Extension.basicConstraints.getId());

        if (rawBasicConstraints == null) {
            return false;
        }

        BasicConstraints basicConstraints = BasicConstraints.getInstance(ASN1OctetString.getInstance(rawBasicConstraints).getOctets());
        return basicConstraints.isCA();
    }

    public static boolean isSelfSigned(X509Certificate certificate) {
        try {
            certificate.verify(certificate.getPublicKey(), new BouncyCastleProvider());
            return true;
        } catch (NoSuchAlgorithmException | CertificateException ex) {
            throw new RuntimeException(ex);
        } catch (InvalidKeyException | SignatureException ex) {
            return false;
        }
    }

    public static boolean isRootCA(X509Certificate certificate) {
        return isSelfSigned(certificate) && isCA(certificate);
    }

    public static boolean isSubCA(X509Certificate certificate) {
        return !isSelfSigned(certificate) && isCA(certificate);
    }

    public static boolean isSubscriberCert(X509Certificate certificate) {

        byte[] rawBasicConstraints = certificate.getExtensionValue(Extension.basicConstraints.getId());

        if (rawBasicConstraints == null) {
            return true;
        }

        byte[] value = ASN1OctetString.getInstance(rawBasicConstraints).getOctets();
        BasicConstraints basicConstraints = BasicConstraints.getInstance(value);
        return !basicConstraints.isCA();
    }

    public static boolean isServerAuthCert(X509Certificate certificate) {

        byte[] rawExtendedKeyUsage = certificate.getExtensionValue(Extension.extendedKeyUsage.getId());

        if (rawExtendedKeyUsage == null) {
            return true;
        }

        byte[] value = ASN1OctetString.getInstance(rawExtendedKeyUsage).getOctets();
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(value);
        return (extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.anyExtendedKeyUsage) ||
                extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth));
    }

    public static boolean isDelegatedOCSPResponderCert(X509Certificate certificate) {

        byte[] rawExtendedKeyUsage = certificate.getExtensionValue(Extension.extendedKeyUsage.getId());

        if (rawExtendedKeyUsage == null) {
            return false;
        }

        byte[] value = ASN1OctetString.getInstance(rawExtendedKeyUsage).getOctets();
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(value);
        return extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_OCSPSigning);
    }


    public static boolean dnsNamesExist(X509Certificate certificate) throws IOException {

        boolean sanDNSNamesExist = !Utils.getDNSNames(certificate).isEmpty();
        List<AttributeTypeAndValue> commonName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.commonName.getId());

        if (commonName.isEmpty()) {
            return sanDNSNamesExist;
        }

        for (AttributeTypeAndValue attributeTypeAndValue : commonName) {
            String value = attributeTypeAndValue.getValue().toString();
            if (!value.isEmpty() && !value.contains("@")) {
                return true;
            }
        }

        return sanDNSNamesExist;

    }

    public static List<String> getDNSNames(X509Certificate certificate) throws IOException {
        return getGeneralNameAsString(certificate, 2);
    }

    public static List<String> getEmails(X509Certificate certificate) throws IOException {
        return getGeneralNameAsString(certificate, 1);
    }

    public static List<String> getIpAddresses(X509Certificate certificate) throws IOException {

        IPAddressNetwork.IPAddressGenerator generator = new IPAddressNetwork.IPAddressGenerator();

        byte[] rawSAN = certificate.getExtensionValue(Extension.subjectAlternativeName.getId());

        if (rawSAN == null) {
            return new ArrayList<>();
        }

        List<GeneralName> generalNames = getGeneralNameList(rawSAN, 7);

        List<String> ipAddresses = new ArrayList<>();

        for (GeneralName generalName : generalNames) {
            ASN1OctetString octetString = (ASN1OctetString) generalName.getName();
            ipAddresses.add(generator.from(octetString.getOctets()).toString());
        }

        return ipAddresses;
    }

    private static List<String> getGeneralNameAsString(X509Certificate certificate, int tag) throws IOException {

        byte[] rawSAN = certificate.getExtensionValue(Extension.subjectAlternativeName.getId());

        if (rawSAN == null) {
            return new ArrayList<>();
        }

        List<GeneralName> generalNames = getGeneralNameList(rawSAN, tag);

        List<String> stringNames = new ArrayList<>();
        generalNames.stream().forEach(generalName -> stringNames.add((generalName.getName()).toString()));
        return stringNames;
    }

    public static List<GeneralName> getDNSNames(byte[] encoded) throws IOException {
        return getGeneralNameList(encoded, 2);
    }

    public static List<GeneralName> getEmails(byte[] encoded) throws IOException {
        return getGeneralNameList(encoded, 1);
    }

    public static List<GeneralName> getUniformResourceIdentifiers(byte[] encoded) throws IOException {
        return getGeneralNameList(encoded, 6);
    }

    private static List<GeneralName> getGeneralNameList(byte[] encoded, int tag) throws IOException {
        GeneralNames generalNames = getGeneralNames(encoded);
        GeneralName[] names = generalNames.getNames();
        List<GeneralName> generalNameList = new ArrayList<>();
        Arrays.stream(names).filter(generalName -> generalName.getTagNo() == tag).forEach(generalNameList::add);
        return generalNameList;
    }

    public static List<GeneralName> getAllGeneralNames(byte[] encoded) throws IOException {
        GeneralNames generalNames = getGeneralNames(encoded);
        GeneralName[] names = generalNames.getNames();
        List<GeneralName> generalNameList = new ArrayList<>();
        Arrays.stream(names).forEach(generalNameList::add);
        return generalNameList;
    }

    public static GeneralNames getGeneralNames(byte[] encoded) throws IOException {
        return GeneralNames.getInstance(((ASN1OctetString) ASN1Primitive.fromByteArray(encoded)).getOctets());
    }

    public static boolean isPublicKeyECC(X509Certificate certificate) {
        return publicKeyHasOID(certificate, X9ObjectIdentifiers.id_ecPublicKey.getId());
    }

    public static boolean isPublicKeyEdDSA(X509Certificate certificate) {
        return publicKeyHasOID(certificate, EdECObjectIdentifiers.id_Ed448.getId()) ||
                publicKeyHasOID(certificate, EdECObjectIdentifiers.id_Ed25519.getId());
    }

    public static boolean isPublicKeyRSA(X509Certificate certificate) {
        return publicKeyHasOID(certificate, PKCSObjectIdentifiers.rsaEncryption.getId());
    }

    public static boolean isPublicKeyDSA(X509Certificate certificate) {
        return publicKeyHasOID(certificate, X9ObjectIdentifiers.id_dsa.getId());
    }

    private static boolean publicKeyHasOID(X509Certificate certificate, String oid) {
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded());
        return subjectPublicKeyInfo.getAlgorithm().getAlgorithm().getId().equalsIgnoreCase(oid);
    }

    public static boolean hasDNSNamesInSANOrSubjectDN(X509Certificate certificate) throws IOException {
        if (!hasDNSNames(certificate)) {
            return false;
        }

        List<AttributeTypeAndValue> commonNames = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.commonName.getId());
        return !commonNames.stream().map(cn -> cn.getValue().toString()).allMatch(Utils::isIPAddress);
    }

    public static boolean hasDNSNames(X509Certificate certificate) throws IOException {
        return !getDNSNames(certificate).isEmpty();
    }

    public static boolean hasExtension(X509Certificate certificate, String oid) {
        return certificate.getExtensionValue(oid) != null;
    }

    public static boolean hasBasicConstraintsExtension(X509Certificate certificate) {
        return hasExtension(certificate, Extension.basicConstraints.getId());
    }

    public static boolean hasKeyUsageExtension(X509Certificate certificate) {
        return hasExtension(certificate, Extension.keyUsage.getId());
    }

    public static boolean hasExtendedKeyUsageExtension(X509Certificate certificate) {
        return hasExtension(certificate, Extension.extendedKeyUsage.getId());
    }

    public static boolean hasAuthorityInformationAccessExtension(X509Certificate certificate) {
        return hasExtension(certificate, Extension.authorityInfoAccess.getId());
    }

    public static boolean hasAuthorityKeyIdentifierExtension(X509Certificate certificate) {
        return hasExtension(certificate, Extension.authorityKeyIdentifier.getId());
    }

    public static boolean hasCertificatePoliciesExtension(X509Certificate certificate) {
        return hasExtension(certificate, Extension.certificatePolicies.getId());
    }

    public static boolean hasCRLDPExtension(X509Certificate certificate) {
        return hasExtension(certificate, Extension.cRLDistributionPoints.getId());
    }

    public static boolean isExtensionCritical(X509Certificate certificate, String oid) {
        Set<String> criticalExtensionOIDs = certificate.getCriticalExtensionOIDs();
        return criticalExtensionOIDs.stream().anyMatch(extensionOID -> extensionOID.equalsIgnoreCase(oid));
    }

    public static boolean isBasicConstraintsExtensionCritical(X509Certificate certificate) {
        return isExtensionCritical(certificate, Extension.basicConstraints.getId());
    }

    public static boolean isAuthorityInformationAccessExtensionCritical(X509Certificate certificate) {
        return isExtensionCritical(certificate, Extension.authorityInfoAccess.getId());
    }

    public static boolean isAuthorityKeyIdentifierExtensionCritical(X509Certificate certificate) {
        return isExtensionCritical(certificate, Extension.authorityKeyIdentifier.getId());
    }

    public static boolean isExtendedKeyUsageExtensionCritical(X509Certificate certificate) {
        return isExtensionCritical(certificate, Extension.extendedKeyUsage.getId());
    }

    public static boolean isCRLDPExtensionCritical(X509Certificate certificate) {
        return isExtensionCritical(certificate, Extension.cRLDistributionPoints.getId());
    }

    public static boolean hasMultiValuedRDNInIssuer(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence issuer = (ASN1Sequence) ASN1CertificateUtils.getIssuer(certificate);
        return hasMultiValuedRDNInDN(issuer);
    }

    public static boolean hasMultiValuedRDNInSubject(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence subject = (ASN1Sequence) ASN1CertificateUtils.getSubject(certificate);
        return hasMultiValuedRDNInDN(subject);
    }

    private static boolean hasMultiValuedRDNInDN(ASN1Sequence rDNSequence) {
        Iterator<ASN1Encodable> iterator = rDNSequence.iterator();
        while (iterator.hasNext()) {
            ASN1Set rdn = (ASN1Set) iterator.next();
            if (rdn.size() > 1) {
                return true;
            }
        }
        return false;
    }

    public static List<String> getAllAttributeValuesInIssuer(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence issuer = (ASN1Sequence) ASN1CertificateUtils.getIssuer(certificate);
        return getAllAttributeValuesInDN(issuer, null);
    }

    public static List<String> getAllAttributeValuesInSubject(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence subject = (ASN1Sequence) ASN1CertificateUtils.getSubject(certificate);
        return getAllAttributeValuesInDN(subject, null);
    }

    public static List<String> getAllAttributeValuesInSubject(X509Certificate certificate, String oid) throws CertificateEncodingException {
        ASN1Sequence subject = (ASN1Sequence) ASN1CertificateUtils.getSubject(certificate);
        return getAllAttributeValuesInDN(subject, oid);
    }

    public static List<String> getAllAttributeTypesInSubject(X509Certificate certificate) throws CertificateEncodingException {
        ASN1Sequence subject = (ASN1Sequence) ASN1CertificateUtils.getSubject(certificate);

        List<String> oids = new ArrayList<>();
        Iterator<ASN1Encodable> iterator = subject.iterator();
        while (iterator.hasNext()) {
            ASN1Set rdn = (ASN1Set) iterator.next();
            Iterator<ASN1Encodable> rdnIterator = rdn.iterator();
            while (rdnIterator.hasNext()) {
                ASN1Sequence attributeTypeAndValue = (ASN1Sequence) rdnIterator.next();
                oids.add(((ASN1ObjectIdentifier) attributeTypeAndValue.getObjectAt(0)).getId());
            }
        }
        return oids;
    }

    private static List<String> getAllAttributeValuesInDN(ASN1Sequence rDNSequence, String oid) {
        List<String> values = new ArrayList<>();
        Iterator<ASN1Encodable> iterator = rDNSequence.iterator();
        while (iterator.hasNext()) {
            ASN1Set rdn = (ASN1Set) iterator.next();
            Iterator<ASN1Encodable> rdnIterator = rdn.iterator();
            while (rdnIterator.hasNext()) {
                ASN1Sequence attributeTypeAndValue = (ASN1Sequence) rdnIterator.next();
                if (oid == null) {
                    values.add(attributeTypeAndValue.getObjectAt(1).toString());
                } else {
                    if (((ASN1ObjectIdentifier) attributeTypeAndValue.getObjectAt(0)).getId().equalsIgnoreCase(oid)) {
                        values.add(attributeTypeAndValue.getObjectAt(1).toString());
                    }
                }
            }
        }
        return values;
    }

    public static boolean isValueIn(int value, List<Integer> valuesToCheck) {
        return valuesToCheck.contains(value);
    }

    public static Optional<byte[]> getAKIEKeyIdentifier(X509Certificate certificate) {

        byte[] akieValue = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());

        if (akieValue == null) {
            return Optional.empty();
        }

        AuthorityKeyIdentifier akie = AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(akieValue).getOctets());

        if (akie == null) {
            return Optional.empty();
        }

        byte[] keyIdentifier = akie.getKeyIdentifier();

        if (keyIdentifier == null) {
            return Optional.empty();
        } else {
            return Optional.of(keyIdentifier);
        }
    }


    public static Optional<byte[]> getSKIEKeyIdentifier(X509Certificate certificate) {

        byte[] skieValue = certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());

        if (skieValue == null) {
            return Optional.empty();
        }

        SubjectKeyIdentifier skie = SubjectKeyIdentifier.getInstance(ASN1OctetString.getInstance(skieValue).getOctets());

        if (skie == null) {
            return Optional.empty();
        }

        byte[] keyIdentifier = skie.getKeyIdentifier();

        if (keyIdentifier == null) {
            return Optional.empty();
        } else {
            return Optional.of(keyIdentifier);
        }
    }


    public static Optional<String> getOCSPURL(X509Certificate certificate) {

        byte[] aiaeValue = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());

        if (aiaeValue == null) {
            return Optional.empty();
        }

        AuthorityInformationAccess aiae = AuthorityInformationAccess.getInstance(ASN1OctetString.getInstance(aiaeValue).getOctets());

        AccessDescription[] accessDescriptions = aiae.getAccessDescriptions();

        for (AccessDescription accessDescription : accessDescriptions) {
            if (X509ObjectIdentifiers.id_ad_ocsp.equals(accessDescription.getAccessMethod())) {
                GeneralName accessLocation = accessDescription.getAccessLocation();
                DERIA5String location = (DERIA5String) accessLocation.getName();
                return Optional.of(location.getString());
            }
        }

        return Optional.empty();
    }

    public static List<ASN1Encodable> getExplicitTextList(X509Certificate certificate) {
        List<ASN1Encodable> explicitTextList = new ArrayList<>();

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(ASN1OctetString.getInstance(rawCertificatePolicies).getOctets());
        for (PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {
            ASN1Sequence policyQualifiersSequence = policyInformation.getPolicyQualifiers();
            if (policyQualifiersSequence == null) {
                return explicitTextList;
            }
            ASN1Encodable[] policyQualifiers = policyQualifiersSequence.toArray();
            for (ASN1Encodable policyQualifier : policyQualifiers) {
                ASN1ObjectIdentifier policyQualifierId = (ASN1ObjectIdentifier) ((ASN1Sequence) policyQualifier).getObjectAt(0);
                if (PolicyQualifierId.id_qt_unotice.getId().equals(policyQualifierId.getId())) {
                    ASN1Encodable qualifier = ((ASN1Sequence) policyQualifier).getObjectAt(1);
                    if (qualifier instanceof ASN1Sequence) {
                        ASN1Sequence seq = (ASN1Sequence) qualifier;

                        if (seq.size() == 2) {
                            explicitTextList.add(((ASN1Sequence) qualifier).getObjectAt(1));
                            continue;
                        }

                        if (seq.size() == 1) {
                            if (!(seq.getObjectAt(0) instanceof ASN1Sequence)) {
                                explicitTextList.add(seq.getObjectAt(0));
                            }
                        }
                    }
                }
            }
        }

        return explicitTextList;
    }

    public static byte[] getContent(GeneralName generalName) throws IOException {
        return getContent(generalName.getEncoded(ASN1Encoding.DER));
    }

    public static byte[] getContent(ASN1UTF8String utfString) throws IOException {
        return getContent(utfString.getEncoded(ASN1Encoding.DER));
    }

    public static byte[] getContent(ASN1BMPString bmpString) throws IOException {
        return getContent(bmpString.getEncoded(ASN1Encoding.DER));
    }

    public static byte[] getContent(ASN1VisibleString visibleString) throws IOException {
        return getContent(visibleString.getEncoded(ASN1Encoding.DER));
    }

    public static List<AttributeTypeAndValue> getIssuerDNNameComponent(X509Certificate certificate, String oid) {
        return getNameComponent(oid, certificate.getIssuerX500Principal().getEncoded());
    }

    public static List<AttributeTypeAndValue> getSubjectDNNameComponent(X509Certificate certificate, String oid) {
        return getNameComponent(oid, certificate.getSubjectX500Principal().getEncoded());
    }

    public static List<AttributeTypeAndValue> getIssuerDNNameComponents(X509Certificate certificate) {
        return getNameComponents(certificate.getIssuerX500Principal().getEncoded());
    }

    public static List<AttributeTypeAndValue> getSubjectDNNameComponents(X509Certificate certificate) {
        return getNameComponents(certificate.getSubjectX500Principal().getEncoded());
    }

    public static boolean isIssuerDNEmpty(X509Certificate certificate) {
        return isDNEmpty(certificate.getIssuerX500Principal().getEncoded());
    }

    public static boolean isSubjectDNEmpty(X509Certificate certificate) {
        return isDNEmpty(certificate.getSubjectX500Principal().getEncoded());
    }

    public static String getPublicKeyOID(X509Certificate certificate) {
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded());
        return subjectPublicKeyInfo.getAlgorithm().getAlgorithm().getId();
    }

    private static boolean isDNEmpty(byte[] encodedDN) {
        return ASN1Sequence.getInstance(encodedDN).size() < 1;
    }

    private static byte[] getContent(byte[] encoded) {

        if (encoded.length == 2) {
            return null;
        }

        if (encoded[1] == (byte) 0x81) {
            int startBytes = 3;
            byte[] result = new byte[encoded.length - startBytes];
            System.arraycopy(encoded, startBytes, result, 0, encoded.length - startBytes);
            return result;
        }
        if (encoded[1] == (byte) 0x82) {
            int startBytes = 4;
            byte[] result = new byte[encoded.length - startBytes];
            System.arraycopy(encoded, startBytes, result, 0, encoded.length - startBytes);
            return result;
        }
        if (encoded[1] == (byte) 0x83) {
            int startBytes = 5;
            byte[] result = new byte[encoded.length - startBytes];
            System.arraycopy(encoded, startBytes, result, 0, encoded.length - startBytes);
            return result;
        }
        if (encoded[1] == (byte) 0x84) {
            int startBytes = 6;
            byte[] result = new byte[encoded.length - startBytes];
            System.arraycopy(encoded, startBytes, result, 0, encoded.length - startBytes);
            return result;
        }

        int startBytes = 2;
        byte[] result = new byte[encoded.length - startBytes];
        System.arraycopy(encoded, startBytes, result, 0, encoded.length - startBytes);
        return result;

    }

    public static List<AttributeTypeAndValue> getNameComponent(String oid, byte[] encodedDN) {

        List<AttributeTypeAndValue> list = new ArrayList<>();

        ASN1Sequence name = ASN1Sequence.getInstance(encodedDN);
        Iterator<ASN1Encodable> iterator = name.iterator();
        while (iterator.hasNext()) {
            ASN1Set rdn = (ASN1Set.getInstance(iterator.next()));
            Iterator<ASN1Encodable> rdnIterator = rdn.iterator();
            while (rdnIterator.hasNext()) {
                AttributeTypeAndValue attributeTypeAndValue = AttributeTypeAndValue.getInstance(rdnIterator.next());
                if (attributeTypeAndValue.getType().getId().equals(oid)) {
                    list.add(attributeTypeAndValue);
                }
            }
        }
        return list;
    }

    private static List<AttributeTypeAndValue> getNameComponents(byte[] encodedDN) {

        List<AttributeTypeAndValue> list = new ArrayList<>();

        ASN1Sequence name = ASN1Sequence.getInstance(encodedDN);
        Iterator<ASN1Encodable> iterator = name.iterator();
        while (iterator.hasNext()) {
            ASN1Set rdn = (ASN1Set.getInstance(iterator.next()));
            Iterator<ASN1Encodable> rdnIterator = rdn.iterator();
            while (rdnIterator.hasNext()) {
                AttributeTypeAndValue attributeTypeAndValue = AttributeTypeAndValue.getInstance(rdnIterator.next());
                list.add(attributeTypeAndValue);
            }
        }
        return list;
    }

    public static boolean componentNameIsEmpty(List<AttributeTypeAndValue> components) {

        if (components.isEmpty()) {
            return true;
        }

        for (AttributeTypeAndValue component : components) {
            String componentValue = component.getValue().toString();
            if (componentValue == null || componentValue.isEmpty()) {
                return true;
            }
        }
        return false;
    }


    public static boolean containsPolicyOID(X509Certificate certificate, String oid) {

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        ASN1OctetString asn1OctetString = ASN1OctetString.getInstance(rawCertificatePolicies);
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(asn1OctetString.getOctets());

        Predicate<PolicyInformation> policyEquals = p -> oid.equals(p.getPolicyIdentifier().getId());
        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(policyEquals);
    }

    public static boolean isIPAddress(String value) {

        if (value == null || value.isEmpty()) {
            return false;
        }

        if (value.contains(":")) {
            try {
                InetAddress.getByName(value);
                return true;
            } catch (UnknownHostException ex) {
                return false;
            }
        } else {
            try {
                InetAddress byName = InetAddress.getByName(value);
                InetAddress byAddress = InetAddress.getByAddress(byName.getAddress());
                return value.equals(byAddress.getHostAddress());
            } catch (UnknownHostException ex) {
                return false;
            }
        }
    }

    public static int getLowestSetBit(byte input) {

        if (input == 0) {
            return 0;
        }

        int counter = 1;

        while ((input & 0x01) != 1) {
            input = (byte) (input >> 1);
            counter = counter + 1;
        }
        return counter;
    }

    public static boolean hasAdobeX509Extensions(X509Certificate certificate) {
        return hasExtension(certificate, ADOBE_TIMESTAMP_OID) || hasExtension(certificate, ADOBE_ARCHIVE_REV_INFO_OID);
    }

    /**
     * Square root for BigInteger is implemented in Java 9. To keep compatibility to Java 8 a very simple implementation
     * is provided.
     *
     * @param number
     * @return
     */
    public static BigInteger calculateSquareRoot(BigInteger number) {

        if (number.toString().length() < 17) {
            double sqrt = Math.sqrt(number.doubleValue());
            return BigInteger.valueOf((long) sqrt);
        }
        double simpleSquareRoot = Math.sqrt(new BigInteger(number.toString().substring(0, 16)).doubleValue());
        BigInteger simpleSquareRootBig = BigInteger.valueOf((long) simpleSquareRoot);
        int numberOfZerosToAdd = (number.toString().length() - simpleSquareRootBig.pow(2).toString().length()) / 2;
        String zerosToAdd = Stream.generate(() -> "0").limit(numberOfZerosToAdd).collect(Collectors.joining());
        BigInteger estimation = new BigInteger(simpleSquareRootBig.toString() + zerosToAdd);
        return babylonianMethod(new BigDecimal(number), new BigDecimal(estimation)).toBigInteger();
    }

    public static boolean hasRSASignatureOID(X509Certificate certificate) {

        List<String> rsaAlgorithmOIDs = Arrays.asList(
                PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(),
                PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(),
                PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(),
                PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(),
                PKCSObjectIdentifiers.sha512_224WithRSAEncryption.getId(),
                PKCSObjectIdentifiers.sha512_256WithRSAEncryption.getId(),
                PKCSObjectIdentifiers.sha224WithRSAEncryption.getId(),
                PKCSObjectIdentifiers.md5WithRSAEncryption.getId());

        return rsaAlgorithmOIDs.contains(certificate.getSigAlgOID());
    }

    private static BigDecimal babylonianMethod(BigDecimal number, BigDecimal estimation) {
        BigDecimal newEstimation = (estimation.add(number.divide(estimation, 30, RoundingMode.FLOOR))).divide(TWO, 30, RoundingMode.FLOOR);
        if (newEstimation.compareTo(estimation) == 0) {
            return newEstimation;
        }
        return babylonianMethod(number, newEstimation);
    }

}
