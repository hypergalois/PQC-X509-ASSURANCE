package de.mtg.jzlint.lints.cabf_br;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

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
        name = "e_dnsname_left_label_wildcard_correct",
        description = "Wildcards in the left label of DNSName should only be *",
        citation = "BRs: 1.6.1, Wildcard Certificate and Wildcard Domain Name",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class DnsnameLeftLabelWildcardCorrect implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> commonName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.commonName.getId());

        for (AttributeTypeAndValue attributeTypeAndValue : commonName) {
            String value = attributeTypeAndValue.getValue().toString();
            if (wildcardInLeftLabelIncorrect(value)) {
                return LintResult.of(Status.ERROR);
            }
        }

        try {
            List<String> dnsNames = Utils.getDNSNames(certificate);
            for (String dnsName : dnsNames) {
                if (wildcardInLeftLabelIncorrect(dnsName)) {
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
        return true;
    }

    private boolean wildcardInLeftLabelIncorrect(String value) {
        String[] labels = value.split("\\.");
        if (labels.length >= 1) {
            if (labels[0].contains("*") && !labels[0].equals("*")) {
                return true;
            }
        }
        return false;
    }
}
