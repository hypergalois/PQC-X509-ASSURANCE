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
 BRs: 7.1.4.2.2
 Certificate Field: subject:organizationalUnitName (OID: 2.5.4.11)
 Required/Optional: Deprecated. Prohibited if the
 subject:organizationName is absent or the certificate is issued on or after
 September 1, 2022.
 This lint check the first requirement, i.e.: Prohibited if the subject:organizationName is absent.
 ************************************************/

@Lint(
        name = "e_subject_contains_organizational_unit_name_and_no_organization_name",
        description = "If a subject organization name is absent then an organizational unit name MUST NOT be included in subject",
        citation = "BRs: 7.1.4.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABFBRs_1_7_9_Date)
public class SubjectContainsOrganizationalUnitNameAndNoOrganizationName implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> organization = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.organization.getId());

        if (organization.isEmpty()) {
            return LintResult.of(Status.ERROR, "subject:organizationalUnitName is prohibited if subject:organizationName is absent");
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return !Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.organizationalUnitName.getId()).isEmpty();
    }

}
