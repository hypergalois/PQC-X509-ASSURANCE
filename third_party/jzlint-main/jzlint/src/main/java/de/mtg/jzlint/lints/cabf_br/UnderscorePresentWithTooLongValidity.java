package de.mtg.jzlint.lints.cabf_br;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.IneffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.DateUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_underscore_present_with_too_long_validity",
        description = "From 2018-12-10 to 2019-04-01, DNSNames may contain underscores if-and-only-if the certificate is valid for less than thirty days.",
        citation = "BR 7.1.4.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABFBRs_1_6_2_Date,
        ineffectiveDate = IneffectiveDate.CABFBRS_1_6_2_UNDERSCORE_PERMISSIBILITY_SUNSET_DATE)
public class UnderscorePresentWithTooLongValidity implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            List<String> dnsNames = Utils.getDNSNames(certificate);

            for (String dnsName : dnsNames) {
                if (dnsName.contains("_")) {
                    return LintResult.of(Status.ERROR, String.format(
                            "The DNSName %s contains an underscore character which is only permissible if the certificate is valid for less than 30 days (this certificate is valid for %d days)",
                            dnsName, DateUtils.getValidityInDaysBeforeSC31(certificate)));
                }
            }
        } catch (IOException e) {
            return LintResult.of(Status.FATAL);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        try {
            int validityInDays = DateUtils.getValidityInDaysBeforeSC31(certificate);
            return Utils.isSubscriberCert(certificate) && Utils.dnsNamesExist(certificate) && validityInDays > 30;
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
