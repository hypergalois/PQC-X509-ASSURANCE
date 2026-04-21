package de.mtg.jzlint.lints.cabf_br;

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
import de.mtg.jzlint.utils.BRUtils;
import de.mtg.jzlint.utils.Utils;

/************************************************
 7.1.2.7.2 Domain Validated

 The following table details the acceptable AttributeTypes that may appear within the type
 field of an AttributeTypeAndValue, as well as the contents permitted within the value field.

 Table 35: Domain Validated subject Attributes

 countryName MAY The two‐letter ISO 3166‐1 country code for the country
 associated with the Subject. Section 3.2.2.3

 commonName NOT RECOMMENDED
 If present, MUST contain a value derived from the
 subjectAltName extension according to Section
 7.1.4.3.

 Any other attribute MUST NOT
 ************************************************/

@Lint(
        name = "e_cab_dv_subject_invalid_values",
        description = "If certificate policy 2.23.140.1.2.1 (CA/B BR domain validated) is included, only country and/or common name is allowed in SubjectDN.",
        citation = "BRs: 7.1.2.7.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SC62_EFFECTIVE_DATE)
public class CabDvSubjectInvalidValues implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        boolean cnFound = false;
        List<AttributeTypeAndValue> subjectDNNameComponents = Utils.getSubjectDNNameComponents(certificate);
        for (AttributeTypeAndValue ava : subjectDNNameComponents) {
            if (ava.getType().getId().equals(BCStyle.C.getId())) {
                continue;
            }
            if (ava.getType().getId().equals(BCStyle.CN.getId())) {
                cnFound = true;
                continue;
            }
            return LintResult.of(Status.ERROR, String.format("DV certificate contains the invalid attribute type %s", ava.getType().getId()));
        }

        if (cnFound) {
            return LintResult.of(Status.WARN, "DV certificate contains a subject common name, this is not recommended.");
        }

        return LintResult.of(Status.PASS);

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) && BRUtils.isDomainValidated(certificate);
    }

}
