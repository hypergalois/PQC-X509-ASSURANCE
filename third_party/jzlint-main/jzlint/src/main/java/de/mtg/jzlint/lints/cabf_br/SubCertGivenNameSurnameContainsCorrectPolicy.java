package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;
import java.util.List;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_sub_cert_given_name_surname_contains_correct_policy",
        description = "Subscriber Certificate: A certificate containing a subject:givenName field or subject:surname field MUST contain the (2.23.140.1.2.3) certPolicy OID.",
        citation = "BRs: 7.1.4.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABGivenNameDate)
public class SubCertGivenNameSurnameContainsCorrectPolicy implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        if (rawCertificatePolicies == null) {
            return LintResult.of(Status.ERROR);
        }

        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(ASN1OctetString.getInstance(rawCertificatePolicies).getOctets());
        for (PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {
            String oid = policyInformation.getPolicyIdentifier().getId();
            if ("2.23.140.1.2.3".equals(oid)) {
                return LintResult.of(Status.PASS);
            }
        }

        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        List<AttributeTypeAndValue> givenName = Utils.getSubjectDNNameComponent(certificate, BCStyle.GIVENNAME.getId());
        List<AttributeTypeAndValue> surname = Utils.getSubjectDNNameComponent(certificate, BCStyle.SURNAME.getId());

        if (givenName.isEmpty() && surname.isEmpty()) {
            return false;
        }

        return Utils.isSubscriberCert(certificate);

    }

}
