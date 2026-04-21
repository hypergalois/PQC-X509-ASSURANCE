package de.mtg.jzlint.lints.cabf_ev;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.style.BCStyle;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.EVUtils;
import de.mtg.jzlint.utils.Utils;


@Lint(
        name = "e_ev_business_category_missing",
        description = "EV certificates must include businessCategory in subject",
        citation = "EVGs: 9.2.3",
        source = Source.CABF_EV_GUIDELINES,
        effectiveDate = EffectiveDate.ZERO)
public class EvBusinessCategoryMissing implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> businessCategory = Utils.getSubjectDNNameComponent(certificate, BCStyle.BUSINESS_CATEGORY.getId());

        if (Utils.componentNameIsEmpty(businessCategory)) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) && EVUtils.isEV(certificate);
    }

}
