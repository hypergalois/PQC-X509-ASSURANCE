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
 Certificate Policy Identifier: 2.23.140.1.2.2
 If the Certificate complies with these Requirements and includes Subject Identity Information
 that is verified in accordance with Section 3.2.2.1.
 Such Certificates MUST also include organizationName, localityName (to the extent such
 field is required under Section 7.1.4.2.2), stateOrProvinceName (to the extent such field is
 required under Section 7.1.4.2.2), and countryName in the Subject field.
 ************************************************/

@Lint(
        name = "e_cert_policy_ov_requires_country",
        description = "If certificate policy 2.23.140.1.2.2 is included, countryName MUST be included in subject",
        citation = "BRs: 7.1.6.4",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class CertPolicyOvRequiresCountry implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> countryName = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.countryName.getId());

        if (countryName.isEmpty()) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) && Utils.containsPolicyOID(certificate, "2.23.140.1.2.2");
    }

}
