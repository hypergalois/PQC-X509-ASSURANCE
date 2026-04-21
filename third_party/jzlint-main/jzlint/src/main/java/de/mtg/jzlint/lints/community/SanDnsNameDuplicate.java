package de.mtg.jzlint.lints.community;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "n_san_dns_name_duplicate",
        description = "SAN DNSName contains duplicate values",
        citation = "awslabs certlint",
        source = Source.COMMUNITY,
        effectiveDate = EffectiveDate.ZERO)
public class SanDnsNameDuplicate implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            List<String> dnsNames = Utils.getDNSNames(certificate);
            Set<String> dnsNamesNew = new HashSet<>();

            for (String dnsName : dnsNames) {
                if (!dnsNamesNew.add(dnsName.toLowerCase())) {
                    return LintResult.of(Status.NOTICE);
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
