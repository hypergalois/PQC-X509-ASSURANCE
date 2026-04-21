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
        name = "e_cab_dv_conflicts_with_org",
        description = "If certificate policy 2.23.140.1.2.1 (CA/B BR domain validated) is included, organization name MUST NOT be included in subject",
        citation = "BRs: 7.1.6.4",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class CabDvConflictsWithOrg implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> organization = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.organization.getId());

        if (!organization.isEmpty()) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.isCA(certificate) && Utils.containsPolicyOID(certificate, "2.23.140.1.2.1");
    }

}
