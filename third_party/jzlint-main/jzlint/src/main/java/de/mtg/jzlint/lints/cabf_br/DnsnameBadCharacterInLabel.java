package de.mtg.jzlint.lints.cabf_br;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_dnsname_bad_character_in_label",
        description = "Characters in labels of DNSNames MUST be alphanumeric, - , _ or *",
        citation = "BRs: 7.1.4.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class DnsnameBadCharacterInLabel implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        Pattern pattern = Pattern.compile("^(\\*\\.)?(\\?\\.)*([A-Za-z0-9*_-]+\\.)*[A-Za-z0-9*_-]*$");

        List<AttributeTypeAndValue> commonName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.commonName.getId());

        for (AttributeTypeAndValue attributeTypeAndValue : commonName) {
            String value = attributeTypeAndValue.getValue().toString();
            if (!value.isEmpty() && !Utils.isIPAddress(value)) {
                Matcher matcher = pattern.matcher(value);
                if (!matcher.matches()) {
                    return LintResult.of(Status.ERROR);
                }
            }
        }

        try {
            List<String> dnsNames = Utils.getDNSNames(certificate);
            for (String dnsName : dnsNames) {
                Matcher matcher = pattern.matcher(dnsName);
                if (!matcher.matches()) {
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
        try {
            return Utils.isSubscriberCert(certificate) && Utils.dnsNamesExist(certificate);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
