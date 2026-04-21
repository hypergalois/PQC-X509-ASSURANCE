package de.mtg.jzlint.lints.cabf_ev;

import java.security.cert.X509Certificate;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.DateUtils;
import de.mtg.jzlint.utils.EVUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_ev_valid_time_too_long",
        description = "EV certificates must be 27 months in validity or less",
        citation = "EVGs 1.0: 8(a), EVGs 1.6.1: 9.4",
        source = Source.CABF_EV_GUIDELINES,
        effectiveDate = EffectiveDate.ZERO)
public class EvValidTimeTooLong implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        int validityInMonths = DateUtils.getValidityInMonthsBeforeSC31(certificate);

        if (validityInMonths > 27) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        boolean issuedBefore = DateUtils.isIssuedBefore(certificate, EffectiveDate.SubCert825Days.getZonedDateTime());

        return issuedBefore && Utils.isSubscriberCert(certificate) && EVUtils.isEV(certificate);
    }

}
