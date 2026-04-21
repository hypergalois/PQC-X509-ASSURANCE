package de.mtg.jlint.smpki.util;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Optional;
import java.util.function.Predicate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.utils.Utils;


/**
 * Utility class providing helper methods for processing structures of the smart meter PKI.
 * <p></p>
 * Relevant specifications:
 * <p></p>
 * <a
 * href="https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03109/PKI_Certificate_Policy.pdf?__blob=publicationFile&v=8">Certificate
 * Policy der Smart Metering PKI Version 1.1.2, 25.01.2023</a>
 * <p></p>
 * <a
 * href="https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03109/TR-03109-4_PKI.pdf?__blob=publicationFile&v=3">Smart Metering PKI - Public Key Infrastruktur für Smart Meter Gateways Version 1.2.1, 09.08.2017</a>
 *
 */
public final class SMPKIUtils {

    public static boolean isSMPKICertificate(X509Certificate certificate) {
        return isSMPKIEnduserCertificate(certificate) ||
                isSMPKIRootTls(certificate) ||
                isSMPKIRootCrlSigner(certificate) ||
                isSMPKIRootTlsSigner(certificate) ||
                isSMPKISubCA(certificate) ||
                isSMPKIRoot(certificate);
    }

    public static boolean isSMPKIEnduserCertificate(X509Certificate certificate) {
        return isSMGWCertificate(certificate) ||
                isEMTCertificate(certificate) ||
                isGWHCertificate(certificate) ||
                isGWACertificate(certificate);
    }

    public static boolean isGWACertificate(X509Certificate certificate) {
        return hasSMPKIPolicy(certificate) && getSMPKICommonName(certificate, "GWA").isPresent();
    }

    public static boolean isGWHCertificate(X509Certificate certificate) {
        return hasSMPKIPolicy(certificate) && getSMPKICommonName(certificate, "GWH").isPresent();
    }

    public static boolean isEMTCertificate(X509Certificate certificate) {
        return hasSMPKIPolicy(certificate) && getSMPKICommonName(certificate, "EMT").isPresent();
    }

    public static boolean isSMGWCertificate(X509Certificate certificate) {
        return hasSMPKIPolicy(certificate) && getSMPKICommonName(certificate, "SMGW").isPresent();
    }

    public static boolean isSMPKIRoot(X509Certificate certificate) {

        if (!hasSMPKIPolicy(certificate)) {
            return false;
        }

        if (!isSMPKIOrganization(certificate)) {
            return false;
        }

        if (!containsCorrectSerialNumber(certificate)) {
            return false;
        }

        if (!isCountry(certificate, "DE")) {
            return false;
        }

        return isCommonName(certificate, "SM-Root.CA") || isCommonName(certificate, "SM-Test-Root.CA");
    }

    public static boolean isSMPKIRootCrlSigner(X509Certificate certificate) {

        if (!hasSMPKIPolicy(certificate)) {
            return false;
        }

        if (!isSMPKIOrganization(certificate)) {
            return false;
        }

        if (!isCountry(certificate, "DE")) {
            return false;
        }

        return isCommonName(certificate, "SM-Root.CA.CRL-S") || isCommonName(certificate, "SM-Test-Root.CA.CRL-S");
    }

    public static boolean isSMPKIRootTlsSigner(X509Certificate certificate) {

        if (!hasSMPKIPolicy(certificate)) {
            return false;
        }

        if (!isSMPKIOrganization(certificate)) {
            return false;
        }

        if (!isCountry(certificate, "DE")) {
            return false;
        }

        if (!containsCorrectSerialNumber(certificate)) {
            return false;
        }

        return isCommonName(certificate, "SM-Root.CA.TLS-S") || isCommonName(certificate, "SM-Test-Root.CA.TLS-S");
    }

    public static boolean isSMPKIRootTls(X509Certificate certificate) {

        if (!hasSMPKIPolicy(certificate)) {
            return false;
        }

        if (!isSMPKIOrganization(certificate)) {
            return false;
        }

        if (!isCountry(certificate, "DE")) {
            return false;
        }

        if (!containsCorrectSerialNumber(certificate)) {
            return false;
        }

        return isCommonName(certificate, "SM-Root.CA.TLS") || isCommonName(certificate, "SM-Test-Root.CA.TLS");
    }


    public static boolean isSMPKISubCA(X509Certificate certificate) {

        if (!hasSMPKIPolicy(certificate)) {
            return false;
        }

        if (!isSMPKIOrganization(certificate)) {
            return false;
        }

        if (!hasCountry(certificate)) {
            return false;
        }

        if (!containsCorrectSerialNumber(certificate)) {
            return false;
        }

        return endsWithCommonName(certificate, ".CA");
    }

    private static Optional<String> getSMPKICommonName(X509Certificate certificate, String expected) {

        if (!isSMPKIOrganization(certificate)) {
            return Optional.empty();
        }

        var commonName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.commonName.getId());

        if (Utils.componentNameIsEmpty(commonName)) {
            return Optional.empty();
        }

        if (commonName.size() != 1) {
            return Optional.empty();
        }

        var commonNameValue = commonName.get(0).getValue().toString();

        if (commonNameValue.endsWith(".%s".formatted(expected))) {
            return Optional.of(commonNameValue);
        } else if (commonNameValue.contains(".%s.".formatted(expected))) {
            return Optional.of(commonNameValue);
        } else {
            return Optional.empty();
        }
    }

    private static boolean isSMPKIOrganization(X509Certificate certificate) {
        var organization = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.organization.getId());

        if (Utils.componentNameIsEmpty(organization)) {
            return false;
        }

        if (organization.size() != 1) {
            return false;
        }

        var organizationValue = organization.get(0).getValue().toString();

        if ("SM-PKI-DE".equals(organizationValue)) {
            return true;
        }

        return "SM-Test-PKI-DE".equals(organizationValue);
    }

    private static boolean containsCorrectSerialNumber(X509Certificate certificate) {

        var serialNumber = Utils.getSubjectDNNameComponent(certificate, BCStyle.SERIALNUMBER.getId());

        if (Utils.componentNameIsEmpty(serialNumber)) {
            return false;
        }

        if (serialNumber.size() != 1) {
            return false;
        }

        var serialNumberValue = serialNumber.get(0).getValue().toString();
        return serialNumberValue.matches("\\d+");
    }

    private static boolean isCountry(X509Certificate certificate, String expectedCountryCode) {

        var country = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.countryName.getId());

        if (Utils.componentNameIsEmpty(country)) {
            return false;
        }

        if (country.size() != 1) {
            return false;
        }

        return expectedCountryCode.equals(country.get(0).getValue().toString());
    }

    private static boolean hasCountry(X509Certificate certificate) {

        var country = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.countryName.getId());

        if (Utils.componentNameIsEmpty(country)) {
            return false;
        }

        return country.size() == 1;
    }

    private static boolean isCommonName(X509Certificate certificate, String expectedValue) {
        var commonName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.commonName.getId());

        if (Utils.componentNameIsEmpty(commonName)) {
            return false;
        }

        if (commonName.size() != 1) {
            return false;
        }

        var commonNameValue = commonName.get(0).getValue().toString();

        return expectedValue.equals(commonNameValue);
    }


    private static boolean endsWithCommonName(X509Certificate certificate, String expectedValue) {
        var commonName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.commonName.getId());

        if (Utils.componentNameIsEmpty(commonName)) {
            return false;
        }

        if (commonName.size() != 1) {
            return false;
        }

        var commonNameValue = commonName.get(0).getValue().toString();

        return expectedValue.endsWith(commonNameValue);
    }

    private static boolean hasSMPKIPolicy(X509Certificate certificate) {

        var rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return false;
        }

        var certificatePolicies = CertificatePolicies.getInstance(ASN1OctetString.getInstance(rawCertificatePolicies).getOctets());

        Predicate<PolicyInformation> isSMPKIPolicy = p -> p.getPolicyIdentifier().equals(new ASN1ObjectIdentifier("0.4.0.127.0.7.3.4.1.1.1"));
        return Arrays.stream(certificatePolicies.getPolicyInformation()).anyMatch(isSMPKIPolicy);
    }

}
