package de.mtg.jzlint.lints.cabf_br;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_underscore_not_permissible_in_dnsname",
        description = "DNSNames MUST NOT contain underscore characters",
        citation = "BR 7.1.4.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABFBRs_1_6_2_UnderscorePermissibilitySunsetDate)
public class UnderscoreNotPermissibleInDnsname implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        try {
            List<String> dnsNames = Utils.getDNSNames(certificate);

            boolean containsUnderscore = dnsNames.stream().anyMatch(d -> d.contains("_"));
            if (containsUnderscore) {
                return LintResult.of(Status.ERROR);
            }
            return LintResult.of(Status.PASS);
        } catch (IOException ex) {
            return LintResult.of(Status.FATAL);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        try {
            return !Utils.getDNSNames(certificate).isEmpty() && Utils.isSubscriberCert(certificate);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
