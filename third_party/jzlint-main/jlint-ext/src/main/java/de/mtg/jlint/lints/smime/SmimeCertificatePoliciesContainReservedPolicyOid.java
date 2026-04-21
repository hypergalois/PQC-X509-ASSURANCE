package de.mtg.jlint.lints.smime;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

/**
 * 7.1.2.3 Subscriber certificates
 * a. certificatePolicies (SHALL be present)
 * This extension SHOULD NOT be marked critical. It SHALL include exactly one of the
 * reserved policyIdentifiers listed in Section 7.1.6.1, and MAY contain one or more
 * identifiers documented by the CA in its CP and/or CPS.
 * If the value of this extension includes a PolicyInformation which contains a qualifier of
 * type id_qt_cps (OID: 1.3.6.1.5.5.7.2.1), then the value of the qualifier SHALL be a HTTP or
 * HTTPS URL for the Issuing CA’s CP and/or CPS, Relying Party Agreement, or other pointer to
 * online policy information provided by the Issuing CA. If a qualifier of type id_qt_unotice
 * (OID: 1.3.6.1.5.5.7.2.2) is included, then it SHALL contain explicitText and SHALL NOT
 * contain noticeRef.
 */
@Lint(
        name = "e_smime_certificate_policies_contain_reserved_policy_oid",
        description = "Check if a subscriber certificate contains exactly one of the reserved policyIdentifiers",
        citation = "SMIME BR 7.1.2.3a",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SmimeCertificatePoliciesContainReservedPolicyOid implements JavaLint {

    private static final String MAILBOX_VALIDATED_LEGACY = "2.23.140.1.5.1.1";
    private static final String MAILBOX_VALIDATED_MULTIPURPOSE = "2.23.140.1.5.1.2";
    private static final String MAILBOX_VALIDATED_STRICT = "2.23.140.1.5.1.3";
    private static final String ORGANIZATION_VALIDATED_LEGACY = "2.23.140.1.5.2.1";
    private static final String ORGANIZATION_VALIDATED_MULTIPURPOSE = "2.23.140.1.5.2.2";
    private static final String ORGANIZATION_VALIDATED_STRICT = "2.23.140.1.5.2.3";
    private static final String SPONSOR_VALIDATED_LEGACY = "2.23.140.1.5.3.1";
    private static final String SPONSOR_VALIDATED_MULTIPURPOSE = "2.23.140.1.5.3.2";
    private static final String SPONSOR_VALIDATED_STRICT = "2.23.140.1.5.3.3";
    private static final String INDIVIDUAL_VALIDATED_LEGACY = "2.23.140.1.5.4.1";
    private static final String INDIVIDUAL_VALIDATED_MULTIPURPOSE = "2.23.140.1.5.4.2";
    private static final String INDIVIDUAL_VALIDATED_STRICT = "2.23.140.1.5.4.3";

    @Override
    public LintResult execute(X509Certificate certificate) {

        List<String> reservedOIDs = Arrays.asList(
                MAILBOX_VALIDATED_LEGACY,
                MAILBOX_VALIDATED_MULTIPURPOSE,
                MAILBOX_VALIDATED_STRICT,
                ORGANIZATION_VALIDATED_LEGACY,
                ORGANIZATION_VALIDATED_MULTIPURPOSE,
                ORGANIZATION_VALIDATED_STRICT,
                SPONSOR_VALIDATED_LEGACY,
                SPONSOR_VALIDATED_MULTIPURPOSE,
                SPONSOR_VALIDATED_STRICT,
                INDIVIDUAL_VALIDATED_LEGACY,
                INDIVIDUAL_VALIDATED_MULTIPURPOSE,
                INDIVIDUAL_VALIDATED_STRICT
        );

        int counter = 0;

        byte[] rawCertificatePolicies = certificate.getExtensionValue(Extension.certificatePolicies.getId());

        byte[] rawValue = ASN1OctetString.getInstance(rawCertificatePolicies).getOctets();
        CertificatePolicies certificatePolicies = CertificatePolicies.getInstance(rawValue);
        for (PolicyInformation policyInformation : certificatePolicies.getPolicyInformation()) {
            String oid = policyInformation.getPolicyIdentifier().getId();
            if (reservedOIDs.contains(oid)) {
                counter += 1;
            }
        }

        if (counter != 1) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return SMIMEUtils.isSMIMEBRSubscriberCertificate(certificate) && Utils.hasCertificatePoliciesExtension(certificate);
    }

}