package de.mtg.jzlint.lints.rfc;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1GeneralizedTime;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.ASN1CertificateUtils;


/********************************************************************
 4.1.2.5.2.  GeneralizedTime
 The generalized time type, GeneralizedTime, is a standard ASN.1 type
 for variable precision representation of time.  Optionally, the
 GeneralizedTime field can include a representation of the time
 differential between local and Greenwich Mean Time.
 For the purposes of this profile, GeneralizedTime values MUST be
 expressed in Greenwich Mean Time (Zulu) and MUST include seconds
 (i.e., times are YYYYMMDDHHMMSSZ), even where the number of seconds
 is zero.  GeneralizedTime values MUST NOT include fractional seconds.
 ********************************************************************/

@Lint(
        name = "e_generalized_time_includes_fraction_seconds",
        description = "Generalized time values MUST NOT include fractional seconds",
        citation = "RFC 5280: 4.1.2.5.2",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC2459)
public class GeneralizedTimeIncludesFractionSeconds implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            if (ASN1CertificateUtils.notBeforeIsGeneralizedTime(certificate)) {
                ASN1GeneralizedTime generalizedTime = (ASN1GeneralizedTime) ASN1CertificateUtils.getNotBefore(certificate);
                if (ASN1CertificateUtils.generalizedTimeHasFractionSeconds(generalizedTime)) {
                    return LintResult.of(Status.ERROR);
                }
            }
            if (ASN1CertificateUtils.notAfterIsGeneralizedTime(certificate)) {
                ASN1GeneralizedTime generalizedTime = (ASN1GeneralizedTime) ASN1CertificateUtils.getNotAfter(certificate);
                if (ASN1CertificateUtils.generalizedTimeHasFractionSeconds(generalizedTime)) {
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
        try {
            return ASN1CertificateUtils.notBeforeIsGeneralizedTime(certificate) || ASN1CertificateUtils.notAfterIsGeneralizedTime(certificate);
        } catch (CertificateEncodingException | IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
