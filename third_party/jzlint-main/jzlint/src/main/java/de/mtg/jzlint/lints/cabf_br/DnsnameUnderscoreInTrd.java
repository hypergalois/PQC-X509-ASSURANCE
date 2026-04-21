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
import de.mtg.jzlint.utils.ParsedDomainName;
import de.mtg.jzlint.utils.ParsedDomainNameUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "w_dnsname_underscore_in_trd",
        description = "DNSName MUST NOT contain underscore characters",
        citation = "BRs: 7.1.4.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.RFC5280)
public class DnsnameUnderscoreInTrd implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            List<ParsedDomainName> parsedDomains = ParsedDomainNameUtils.getParsedDomains(certificate);

            if (ParsedDomainNameUtils.containsError(parsedDomains)) {
                return LintResult.of(Status.NA);
            }

            List<String> trds = ParsedDomainNameUtils.getTRDs(parsedDomains);

            boolean containsUnderscore = trds.stream().anyMatch(trd -> trd.contains("_"));

            if (containsUnderscore) {
                return LintResult.of(Status.WARN);
            }
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        try {
            return Utils.isSubscriberCert(certificate) && Utils.dnsNamesExist(certificate);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
