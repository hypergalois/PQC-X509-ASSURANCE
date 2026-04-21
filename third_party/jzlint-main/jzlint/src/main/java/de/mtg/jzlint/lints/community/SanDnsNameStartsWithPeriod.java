package de.mtg.jzlint.lints.community;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_san_dns_name_starts_with_period",
        description = "DNSName MUST NOT start with a period",
        citation = "awslabs certlint",
        source = Source.COMMUNITY,
        effectiveDate = EffectiveDate.ZERO)
public class SanDnsNameStartsWithPeriod implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            List<String> dnsNames = Utils.getDNSNames(certificate);
            for (String dnsName : dnsNames) {
                if (dnsName.startsWith(".")) {
                    return LintResult.of(Status.ERROR);
                }
            }
        } catch (IOException ex) {
            return LintResult.of(Status.FATAL);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasExtension(certificate, Extension.subjectAlternativeName.getId());
    }

}
