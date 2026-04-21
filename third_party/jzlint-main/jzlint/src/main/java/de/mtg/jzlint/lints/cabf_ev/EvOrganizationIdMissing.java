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
        name = "e_ev_organization_id_missing",
        description = "Effective January 31, 2020, if the subject:organizationIdentifier field is present, this [cabfOrganizationIdentifier] field MUST be present.",
        citation = "CA/Browser Forum EV Guidelines v1.7.0, Sec. 9.8.2",
        source = Source.CABF_EV_GUIDELINES,
        effectiveDate = EffectiveDate.CABV170Date)
public class EvOrganizationIdMissing implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        final String cabfOrganizationIdentifierOID = "2.23.140.3.1";

        if (!Utils.hasExtension(certificate, cabfOrganizationIdentifierOID)) {
            return LintResult.of(Status.ERROR, "subject:organizationIdentifier field is present in an EV certificate but the CA/Browser Forum Organization Identifier Field Extension is missing");
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        if (!EVUtils.isEV(certificate)) {
            return false;
        }

        List<AttributeTypeAndValue> organizationIdentifier = Utils.getSubjectDNNameComponent(certificate, BCStyle.ORGANIZATION_IDENTIFIER.getId());

        return !organizationIdentifier.isEmpty();
    }

}
