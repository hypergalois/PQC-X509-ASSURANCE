package de.mtg.jzlint.lints.cabf_smime_br;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_adobe_extensions_legacy_multipurpose_criticality",
        description = "If present, Adobe Time-stamp X509 extension (1.2.840.113583.1.1.9.1) or the Adobe ArchiveRevInfo extension (1.2.840.113583.1.1.9.2) SHALL NOT be marked as critical for multipurpose/legacy SMIME certificates",
        citation = "7.1.2.3.m",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class AdobeExtensionsLegacyMultipurposeCriticality implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (Utils.isExtensionCritical(certificate, Utils.ADOBE_TIMESTAMP_OID)) {
            return LintResult.of(Status.ERROR);
        }
        if (Utils.isExtensionCritical(certificate, Utils.ADOBE_ARCHIVE_REV_INFO_OID)) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        return Utils.isSubscriberCert(certificate) &&
                (SMIMEUtils.isLegacySMIMECertificate(certificate)
                        || SMIMEUtils.isMultipurposeSMIMECertificate(certificate)) &&
                Utils.hasAdobeX509Extensions(certificate);
    }

}
