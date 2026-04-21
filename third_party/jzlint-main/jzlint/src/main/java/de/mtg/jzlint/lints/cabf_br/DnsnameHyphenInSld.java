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
        name = "e_dnsname_hyphen_in_sld",
        description = "DNSName should not have a hyphen beginning or ending the SLD",
        citation = "BRs 7.1.4.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.RFC5280)
public class DnsnameHyphenInSld implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            List<ParsedDomainName> parsedDomains = ParsedDomainNameUtils.getParsedDomains(certificate);

            if (ParsedDomainNameUtils.containsError(parsedDomains)) {
                return LintResult.of(Status.NA);
            }

            List<String> sLDs = ParsedDomainNameUtils.getSLDs(parsedDomains);

            boolean startsWithHyphen = sLDs.stream().anyMatch(sld -> sld.startsWith("-"));

            if (startsWithHyphen) {
                return LintResult.of(Status.ERROR);
            }

            boolean endsWithHyphen = sLDs.stream().anyMatch(sld -> sld.endsWith("-"));

            if (endsWithHyphen) {
                return LintResult.of(Status.ERROR);
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
