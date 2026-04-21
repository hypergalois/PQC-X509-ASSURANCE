package de.mtg.jzlint.lints.cabf_smime_br;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_authority_key_identifier_correct",
        description = "authorityKeyIdentifier SHALL be present. This extension SHALL NOT be marked critical. The keyIdentifier field SHALL be present. authorityCertIssuer and authorityCertSerialNumber fields SHALL NOT be present.",
        citation = "7.1.2.3.g",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class AuthorityKeyIdentifierCorrect implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (!Utils.hasExtension(certificate, Extension.authorityKeyIdentifier.getId())) {
            return LintResult.of(Status.ERROR, "missing authorityKeyIdentifier");
        }

        if (Utils.isExtensionCritical(certificate, Extension.authorityKeyIdentifier.getId())) {
            return LintResult.of(Status.ERROR, "authorityKeyIdentifier is critical");
        }

        byte[] rawAKIE = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        byte[] rawValue = ASN1OctetString.getInstance(rawAKIE).getOctets();
        AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(rawValue);

        if (authorityKeyIdentifier.getKeyIdentifier() == null) {
            return LintResult.of(Status.ERROR, "keyIdentifier not present");
        }

        if (authorityKeyIdentifier.getAuthorityCertIssuer() != null) {
            return LintResult.of(Status.ERROR, "authorityCertIssuer is present");
        }

        if (authorityKeyIdentifier.getAuthorityCertSerialNumber() != null) {
            return LintResult.of(Status.ERROR, "authorityCertSerialNumber is present");
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) && SMIMEUtils.isSMIMEBRCertificate(certificate);
    }

}
