package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.DateUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_sub_cert_valid_time_longer_than_39_months",
        description = "Subscriber Certificates issued after 1 July 2016 but prior to 1 March 2018 MUST have a Validity Period no greater than 39 months.",
        citation = "BRs: 6.3.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SubCert39Month)
public class SubCertValidTimeLongerThan39Months implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        int validityInMonths = DateUtils.getValidityInMonthsBeforeSC31(certificate);

        if (validityInMonths > 39) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate);
    }

}