package de.mtg.jzlint.lints.cabf_br;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
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


/************************************************
 If present, this field MUST contain exactly one entry that is one of the values contained
 in the Certificate's `subjectAltName` extension
 If the [subject:commonName] is a Fully-Qualified Domain Name or Wildcard Domain Name, then
 the value MUST be encoded as a character-for-character copy of the dNSName entry value from
 the subjectAltName extension.
 ************************************************/

@Lint(
        name = "e_subject_common_name_not_exactly_from_san",
        description = "The common name field in subscriber certificates must include only names from the SAN extension",
        citation = "BRs: 7.1.4.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABFBRs_1_8_0_Date)
public class SubjectCommonNameNotExactlyFromSan implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> commonName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.commonName.getId());

        List<String> sanValues = new ArrayList<>();

        try {
            List<String> dnsNames = Utils.getDNSNames(certificate);
            List<String> ipAddresses = Utils.getIpAddresses(certificate);
            sanValues.addAll(dnsNames);
            sanValues.addAll(ipAddresses);
        } catch (IOException e) {
            return LintResult.of(Status.FATAL);
        }

        for (AttributeTypeAndValue attributeTypeAndValue : commonName) {
            String value = attributeTypeAndValue.getValue().toString();
            if (!sanValues.contains(value)) {
                return LintResult.of(Status.ERROR);
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        List<AttributeTypeAndValue> commonName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.commonName.getId());
        return !Utils.isCA(certificate) && !commonName.isEmpty();
    }

}
