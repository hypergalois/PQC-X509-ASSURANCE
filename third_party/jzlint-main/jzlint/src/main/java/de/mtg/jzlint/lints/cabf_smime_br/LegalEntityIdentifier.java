package de.mtg.jzlint.lints.cabf_smime_br;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_legal_entity_identifier",
        description = "Mailbox/individual: prohibited. Organization/sponsor: may be present",
        citation = "7.1.2.3.l",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class LegalEntityIdentifier implements JavaLint {

    private static final ASN1ObjectIdentifier LEGAL_ENTITY_IDENTIFIER_OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.52266.1");
    private static final ASN1ObjectIdentifier LEGAL_ENTITY_IDENTIFIER_ROLE_OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.52266.2");

    @Override
    public LintResult execute(X509Certificate certificate) {

        boolean leiIsPresent = Utils.hasExtension(certificate, LEGAL_ENTITY_IDENTIFIER_OID.getId());
        boolean leiIsCritical = Utils.isExtensionCritical(certificate, LEGAL_ENTITY_IDENTIFIER_OID.getId());
        boolean leiRoleIsPresent = Utils.hasExtension(certificate, LEGAL_ENTITY_IDENTIFIER_ROLE_OID.getId());
        boolean leiRoleIsCritical = Utils.isExtensionCritical(certificate, LEGAL_ENTITY_IDENTIFIER_ROLE_OID.getId());

        if (SMIMEUtils.isMailboxValidatedCertificate(certificate) || SMIMEUtils.isIndividualValidatedCertificate(certificate)) {
            if (leiIsPresent) {
                return LintResult.of(Status.ERROR, "Legal Entity Identifier extension present");
            }
        }

        if (SMIMEUtils.isOrganizationValidatedCertificate(certificate)) {
            if (leiIsPresent && leiIsCritical) {
                return LintResult.of(Status.ERROR, "Legal Entity Identifier extension present and critical");
            }
            if (leiRoleIsPresent) {
                return LintResult.of(Status.ERROR, "Legal Entity Identifier Role extension present");
            }
        }

        if (SMIMEUtils.isSponsorValidatedCertificate(certificate)) {
            if (leiIsPresent && leiIsCritical) {
                return LintResult.of(Status.ERROR, "Legal Entity Identifier extension present and critical");
            }
            if (leiRoleIsPresent && leiRoleIsCritical) {
                return LintResult.of(Status.ERROR, "Legal Entity Identifier Role extension present and critical");
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) && SMIMEUtils.isSMIMEBRCertificate(certificate);
    }

}
