package de.mtg.jzlint.lints.cabf_br;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.ZonedDateTime;
import java.util.List;
import java.util.stream.Collectors;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.DateUtils;
import de.mtg.jzlint.utils.GTLDUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_dnsname_not_valid_tld",
        description = "DNSNames must have a valid TLD.",
        citation = "BRs: 3.2.2.4",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class DnsnameNotValidTld implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {

            List<AttributeTypeAndValue> commonName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.commonName.getId());

            ZonedDateTime notBefore = DateUtils.getNotBefore(certificate);

            List<String> subjectDNDNSnames = commonName.stream().map(cn -> cn.getValue().toString()).filter(c -> !Utils.isIPAddress(c)).collect(Collectors.toList());

            List<String> dnsNames = Utils.getDNSNames(certificate);
            dnsNames.addAll(subjectDNDNSnames);

            for (String dnsName : dnsNames) {
                if (GTLDUtils.gtldDidnotExist(dnsName, notBefore)) {
                    return LintResult.of(Status.ERROR);
                }
            }
        } catch (IOException | ParseException ex) {
            return LintResult.of(Status.FATAL);
        }

        return LintResult.of(Status.PASS);

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        try {
            return Utils.isSubscriberCert(certificate) && Utils.hasDNSNamesInSANOrSubjectDN(certificate);
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
