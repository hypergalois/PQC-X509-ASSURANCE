package de.mtg.jzlint.lints.cabf_ev;

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
import de.mtg.jzlint.utils.EVUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_ev_country_name_missing",
        description = "EV certificates must include countryName in subject",
        citation = "EVGs: 9.2.4",
        source = Source.CABF_EV_GUIDELINES,
        effectiveDate = EffectiveDate.ZERO)
public class EvCountryNameMissing implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> country = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.countryName.getId());

        if (Utils.componentNameIsEmpty(country)) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) && EVUtils.isEV(certificate);
    }

}
