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
        name = "e_sub_cert_valid_time_longer_than_825_days",
        description = "Subscriber Certificates issued after 1 March 2018, but prior to 1 September 2020, MUST NOT have a Validity Period greater than 825 days.",
        citation = "BRs: 6.3.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SubCert825Days)
public class SubCertValidTimeLongerThan825Days implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        int validityInDays = DateUtils.getValidityInDaysBeforeSC31(certificate);

        if (validityInDays > 825) {
            return LintResult.of(Status.ERROR, String.format("NotBefore: %s, NotAfter: %s", DateUtils.getNotBefore(certificate), DateUtils.getNotAfter(certificate)));
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate);
    }

}