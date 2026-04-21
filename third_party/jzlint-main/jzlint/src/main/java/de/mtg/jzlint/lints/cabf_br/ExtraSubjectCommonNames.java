package de.mtg.jzlint.lints.cabf_br;

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
        name = "w_extra_subject_common_names",
        description = "if present the subject commonName field MUST contain a single IP address or Fully-Qualified Domain Name",
        citation = "BRs: 7.1.4.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class ExtraSubjectCommonNames implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> commonNames = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.commonName.getId());

        if (commonNames.size() > 1) {
            return LintResult.of(Status.WARN);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate);
    }

}
