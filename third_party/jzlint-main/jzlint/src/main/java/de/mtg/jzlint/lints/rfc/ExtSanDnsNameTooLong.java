package de.mtg.jzlint.lints.rfc;

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
        name = "e_ext_san_dns_name_too_long",
        description = "DNSName must be less than or equal to 253 bytes",
        citation = "RFC 5280",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class ExtSanDnsNameTooLong implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            List<String> dnsNames = Utils.getDNSNames(certificate);
            for (String dnsName : dnsNames) {
                if (dnsName.length() > 253) {
                    return LintResult.of(Status.ERROR);
                }
            }
            return LintResult.of(Status.PASS);
        } catch (IOException ex) {
            return LintResult.of(Status.FATAL);
        }
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        try {
            return Utils.hasExtension(certificate, Extension.subjectAlternativeName.getId()) && !Utils.getDNSNames(certificate).isEmpty();
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }
}
