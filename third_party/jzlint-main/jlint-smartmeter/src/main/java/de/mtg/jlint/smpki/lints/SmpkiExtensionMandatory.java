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
        name = "e_smpki_extension_mandatory",
        description = "Certain extensions must be critical and some not.",
        citation = "Technische Richtlinie BSI TR-03109-4, Section A.2",
        source = Source.SM_PKI,
        effectiveDate = EffectiveDate.TR_03109_4_V1_2_1)
public class SmpkiExtensionMandatory implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        boolean isCritical = Utils.isExtensionCritical(certificate, Extension.authorityKeyIdentifier.getId());
        if (isCritical) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI certificate, but has a critical authority key identifier extension.");
        }

        isCritical = Utils.isExtensionCritical(certificate, Extension.subjectKeyIdentifier.getId());

        if (isCritical) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI certificate, but has a critical subject key identifier extension.");
        }

        isCritical = Utils.isExtensionCritical(certificate, Extension.keyUsage.getId());

        if (!isCritical) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI certificate, but has a non-critical key usage extension.");
        }

        isCritical = Utils.isExtensionCritical(certificate, Extension.privateKeyUsagePeriod.getId());

        if (isCritical) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI certificate, but has a critical private key usage period extension.");
        }

        isCritical = Utils.isExtensionCritical(certificate, Extension.certificatePolicies.getId());

        if (isCritical) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI certificate, but has a critical certificate policies extension.");
        }

        isCritical = Utils.isExtensionCritical(certificate, Extension.subjectAlternativeName.getId());

        if (isCritical) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI certificate, but has a critical subject alternative name extension.");
        }

        isCritical = Utils.isExtensionCritical(certificate, Extension.issuerAlternativeName.getId());

        if (isCritical) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI certificate, but has a critical issuer alternative name extension.");
        }

        isCritical = Utils.isExtensionCritical(certificate, Extension.basicConstraints.getId());

        if (!isCritical) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI certificate, but has a non-critical basic constraints extension.");
        }

        isCritical = Utils.isExtensionCritical(certificate, Extension.extendedKeyUsage.getId());

        if (!isCritical) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI certificate, but has a non-critical extended key usage extension.");
        }

        isCritical = Utils.isExtensionCritical(certificate, Extension.cRLDistributionPoints.getId());

        if (isCritical) {
            return LintResult.of(Status.ERROR,
                    "Certificate is an SM-PKI certificate, but has a critical CRL distribution points extension.");
        }

        return LintResult.of(Status.PASS);

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return SMPKIUtils.isSMPKICertificate(certificate);
    }

}