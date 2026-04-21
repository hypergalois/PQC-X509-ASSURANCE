package de.mtg.jzlint.lints.mozilla;

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
import de.mtg.jzlint.utils.Utils;

/********************************************************************
 Section 5.2 - Forbidden and Required Practices
 CAs MUST NOT issue certificates that have:
 - incorrect extensions (e.g., SSL certificates that exclude SSL usage, or authority key IDs
 that include both the key ID and the issuer’s issuer name and serial number);
 ********************************************************************/

@Lint(
        name = "e_mp_authority_key_identifier_correct",
        description = "CAs MUST NOT issue certificates that have authority key IDs that include both the key ID and the issuer's issuer name and serial number",
        citation = "Mozilla Root Store Policy / Section 5.2",
        source = Source.MOZILLA_ROOT_STORE_POLICY,
        effectiveDate = EffectiveDate.MozillaPolicy22Date)
public class MpAuthorityKeyIdentifierCorrect implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawAKI = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());

        AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(ASN1OctetString.getInstance(rawAKI).getOctets());


        if (authorityKeyIdentifier.getKeyIdentifier() != null && authorityKeyIdentifier.getAuthorityCertIssuer() != null) {
            return LintResult.of(Status.ERROR);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasAuthorityKeyIdentifierExtension(certificate);
    }

}
