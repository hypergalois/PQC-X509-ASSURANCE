package de.mtg.jzlint.lints.community;

import java.security.cert.X509Certificate;
import java.time.ZonedDateTime;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.DateUtils;

@Lint(
        name = "e_validity_time_not_positive",
        description = "Certificates MUST have a positive time for which they are valid",
        citation = "lint.AWSLabs certlint",
        source = Source.COMMUNITY,
        effectiveDate = EffectiveDate.ZERO)
public class ValidityTimeNotPositive implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        ZonedDateTime notBefore = DateUtils.getNotBefore(certificate);
        ZonedDateTime notAfter = DateUtils.getNotAfter(certificate);

        if (notBefore.isAfter(notAfter)) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return true;
    }

}
