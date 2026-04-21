package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.style.BCStyle;
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
 Certificate Policy Identifier: 2.23.140.1.2.3
 If the Certificate complies with these Requirements and includes Subject Identity Information
 that is verified in accordance with Section 3.2.3.
 Such Certificates MUST also include either organizationName or both givenName and
 surname, localityName (to the extent such field is required under Section 7.1.4.2.2),
 stateOrProvinceName (to the extent required under Section 7.1.4.2.2), and countryName in
 the Subject field.
 ************************************************/

@Lint(
        name = "e_cab_iv_requires_personal_name",
        description = "If certificate policy 2.23.140.1.2.3 is included, either organizationName or givenName and surname MUST be included in subject",
        citation = "BRs: 7.1.6.4",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABV131Date)
public class CabIvRequiresPersonalName implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> organization = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.organization.getId());

        if (!organization.isEmpty()) {
            return LintResult.of(Status.PASS);
        }

        List<AttributeTypeAndValue> givenName = Utils.getSubjectDNNameComponent(certificate, BCStyle.GIVENNAME.getId());
        List<AttributeTypeAndValue> surname = Utils.getSubjectDNNameComponent(certificate, BCStyle.SURNAME.getId());

        if (givenName.isEmpty()|| surname.isEmpty()) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.isCA(certificate) && Utils.containsPolicyOID(certificate, "2.23.140.1.2.3");
    }

}
