package de.mtg.jlint.smpki.lints;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jlint.smpki.util.SMPKIUtils;
import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_smpki_enduser_extension_present",
        description = "Tabelle 18: Zertifikats-Extensions fuer Endnutzer-Zertifikate (sortiert nach Endnutzer)",
        citation = "Technische Richtlinie BSI TR-03109-4, Section A.2",
        source = Source.SM_PKI,
        effectiveDate = EffectiveDate.TR_03109_4_V1_2_1)
public class SmpkiEnduserExtensionPresent implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        boolean hasExtension = Utils.hasAuthorityKeyIdentifierExtension(certificate);
        if (!hasExtension) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI enduser certificate, but does not have the authority key identifier extension.");
        }

        hasExtension = Utils.hasExtension(certificate, Extension.subjectKeyIdentifier.getId());
        if (!hasExtension) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI enduser certificate, but does not have the subject key identifier extension.");
        }

        hasExtension = Utils.hasKeyUsageExtension(certificate);
        if (!hasExtension) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI enduser certificate, but does not have the key usage extension.");
        }

        hasExtension = Utils.hasExtension(certificate, Extension.privateKeyUsagePeriod.getId());
        if (hasExtension) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI enduser certificate, but has the private key usage period extension.");
        }

        hasExtension = Utils.hasCertificatePoliciesExtension(certificate);
        if (!hasExtension) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI enduser certificate, but does not have the certificate policies extension.");
        }

        hasExtension = Utils.hasExtension(certificate, Extension.subjectAlternativeName.getId());
        if (!hasExtension) {
            if (SMPKIUtils.isGWACertificate(certificate) || SMPKIUtils.isGWHCertificate(certificate) || SMPKIUtils.isEMTCertificate(certificate)) {
                return LintResult.of(Status.ERROR,
                        "Certificate is an SM-PKI enduser of type GWA, GWH, or EMT certificate, but does not have the subject alternative name extension.");
            }
        } else {
            if (SMPKIUtils.isSMGWCertificate(certificate)) {
                return LintResult.of(Status.ERROR,
                        "Certificate is an SM-PKI enduser of type SMGW, but has the subject alternative name extension.");
            }
        }

        hasExtension = Utils.hasExtension(certificate, Extension.issuerAlternativeName.getId());
        if (!hasExtension) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI enduser certificate, but does not have the issuer alternative name extension.");
        }

        hasExtension = Utils.hasBasicConstraintsExtension(certificate);
        if (!hasExtension) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI enduser certificate, but does not have the basic constraints extension.");
        }

        hasExtension = Utils.hasCRLDPExtension(certificate);
        if (!hasExtension) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI enduser certificate, but does not have the CRL distribution points extension.");
        }

        return LintResult.of(Status.PASS);

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return SMPKIUtils.isSMPKIEnduserCertificate(certificate);
    }

}