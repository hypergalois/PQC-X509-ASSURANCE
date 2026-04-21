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

@Lint(
        name = "e_sub_cert_province_must_appear",
        description = "Subscriber Certificate: subject:stateOrProvinceName MUST appear if the subject:organizationName, subject:givenName, or subject:surname fields are present and subject:localityName is absent.",
        citation = "BRs: 7.1.4.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABGivenNameDate)
public class SubCertProvinceMustAppear implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<AttributeTypeAndValue> organization = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.organization.getId());
        List<AttributeTypeAndValue> givenName = Utils.getSubjectDNNameComponent(certificate, BCStyle.GIVENNAME.getId());
        List<AttributeTypeAndValue> surname = Utils.getSubjectDNNameComponent(certificate, BCStyle.SURNAME.getId());

        if (!organization.isEmpty() || !givenName.isEmpty() || !surname.isEmpty()) {
            List<AttributeTypeAndValue> state = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.stateOrProvinceName.getId());
            List<AttributeTypeAndValue> locality = Utils.getSubjectDNNameComponent(certificate, X509ObjectIdentifiers.localityName.getId());
            if (locality.isEmpty() && state.isEmpty()) {
                return LintResult.of(Status.ERROR);
            }
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate);
    }


}
