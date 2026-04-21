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
import de.mtg.jzlint.utils.Utils;

/************************************************
 BRs: 7.1.6.4
 Certificate Policy Identifier: 2.23.140.1.2.1
 If the Certificate complies with these requirements and lacks Subject identity information that
 has been verified in accordance with Section 3.2.2.1 or Section 3.2.3.
 Such Certificates MUST NOT include organizationName, givenName, surname,
 streetAddress, localityName, stateOrProvinceName, or postalCode in the Subject
 field.
 ************************************************/

@Lint(
        name = "e_cab_dv_conflicts_with_postal",
        description = "If certificate policy 2.23.140.1.2.1 (CA/B BR domain validated) is included, postalCode MUST NOT be included in subject",
        citation = "BRs: 7.1.6.4",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class CabDvConflictsWithPostal implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> postalCode = Utils.getSubjectDNNameComponent(certificate, BCStyle.POSTAL_CODE.getId());

        if (!postalCode.isEmpty()) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.isCA(certificate) && Utils.containsPolicyOID(certificate, "2.23.140.1.2.1");
    }

}
