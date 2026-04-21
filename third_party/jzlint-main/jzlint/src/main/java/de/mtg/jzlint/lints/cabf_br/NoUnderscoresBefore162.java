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
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_no_underscores_before_1_6_2",
        description = "Before explicitly stating as such in CABF 1.6.2, the stance of RFC5280 is adopted that DNSNames MUST NOT contain an underscore character.",
        citation = "BR 7.1.4.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.ZERO,
        ineffectiveDate = IneffectiveDate.CABFBRs_1_6_2_Date)
public class NoUnderscoresBefore162 implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            List<String> dnsNames = Utils.getDNSNames(certificate);
            for (String dnsName : dnsNames) {
                if (dnsName.contains("_")) {
                    return LintResult.of(Status.ERROR, String.format("The DNS name '%s' contains an underscore (_) character", dnsName));
                }
            }

        } catch (IOException ex) {
            return LintResult.of(Status.FATAL);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        try {
            return Utils.isSubscriberCert(certificate) && !Utils.getDNSNames(certificate).isEmpty();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
