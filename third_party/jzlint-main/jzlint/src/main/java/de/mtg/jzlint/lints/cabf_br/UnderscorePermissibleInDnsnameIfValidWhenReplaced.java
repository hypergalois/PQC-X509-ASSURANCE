package de.mtg.jzlint.lints.cabf_br;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.IneffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.DomainStringUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_underscore_permissible_in_dnsname_if_valid_when_replaced",
        description = "From December 10th 2018 to April 1st 2019 DNSNames may contain underscores if-and-only-if every label within each DNS name is a valid LDH label after replacing all underscores with hyphens",
        citation = "BR 7.1.4.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABFBRs_1_6_2_Date,
        ineffectiveDate = IneffectiveDate.CABFBRS_1_6_2_UNDERSCORE_PERMISSIBILITY_SUNSET_DATE)
public class UnderscorePermissibleInDnsnameIfValidWhenReplaced implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            List<String> commonName = Utils.getAllAttributeValuesInSubject(certificate, X509ObjectIdentifiers.commonName.getId());
            List<String> dnsNames = Utils.getDNSNames(certificate);
            dnsNames.addAll(commonName);
            for (String dnsName : dnsNames) {
                String[] labels = dnsName.split("\\.");
                for (String label : labels) {

                    if (!label.contains("_") || label.equals("*")) {
                        continue;
                    }
                    String replaced = label.replaceAll("_", "-");
                    if (!DomainStringUtils.isLDHLabel(replaced)) {
                        return LintResult.of(Status.ERROR, String.format("When all underscores (_) in %s are replaced with hypens (-) the result is %s which not a valid LDH label", label, replaced));
                    }
                }
            }

        } catch (CertificateEncodingException | IOException ex) {
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
