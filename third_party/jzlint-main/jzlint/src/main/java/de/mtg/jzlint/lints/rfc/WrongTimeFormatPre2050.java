package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Date;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.ASN1CertificateUtils;

/*********************************************************************
 CAs conforming to this profile MUST always encode certificate
 validity dates through the year 2049 as UTCTime; certificate validity
 dates in 2050 or later MUST be encoded as GeneralizedTime.
 Conforming applications MUST be able to process validity dates that
 are encoded in either UTCTime or GeneralizedTime.
 *********************************************************************/
@Lint(
        name = "e_wrong_time_format_pre2050",
        description = "Certificates valid through the year 2049 MUST be encoded in UTC time",
        citation = "RFC 5280: 4.1.2.5",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class WrongTimeFormatPre2050 implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {

            Date notBefore = certificate.getNotBefore();

            if (isDateIn2050(notBefore)) {
                if (!ASN1CertificateUtils.notBeforeIsGeneralizedTime(certificate)) {
                    return LintResult.of(Status.ERROR);
                }
            } else {
                if (ASN1CertificateUtils.notBeforeIsGeneralizedTime(certificate)) {
                    return LintResult.of(Status.ERROR);
                }
            }

            Date notAfter = certificate.getNotAfter();

            if (isDateIn2050(notAfter)) {
                if (!ASN1CertificateUtils.notAfterIsGeneralizedTime(certificate)) {
                    return LintResult.of(Status.ERROR);
                }
            } else {
                if (ASN1CertificateUtils.notAfterIsGeneralizedTime(certificate)) {
                    return LintResult.of(Status.ERROR);
                }
            }
        } catch (CertificateEncodingException | IOException ex) {
            return LintResult.of(Status.FATAL);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }

    private static boolean isDateIn2050(Date certificateDate) {
        return !isBefore2050(certificateDate);
    }

    private static boolean isBefore2050(Date certificateDate) {
        ZonedDateTime certificateZonedDateTime = ZonedDateTime.ofInstant(certificateDate.toInstant(), ZoneId.of("UTC"));
        return certificateZonedDateTime.isBefore(EffectiveDate.GeneralizedDate.getZonedDateTime());
    }

}
