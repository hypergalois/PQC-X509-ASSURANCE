package de.mtg.jlint.lints.rfc;

import java.security.cert.X509CRL;
import java.util.Arrays;
import java.util.function.Predicate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaCRLLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.CRLUtils;

/**
 * When present in a CRL, this extension MUST include at least one
 * AccessDescription specifying id-ad-caIssuers as the accessMethod.
 */

@Lint(
        name = "e_crl_aia_extension_ca_issuers_present",
        description = "Check if the CRL contains at least one AccessDescription specifying id-ad-caIssuers as the accessMethod in the AIA extension.",
        citation = "RFC 5280, Sec. 5.2.7",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class CrlAiaExtensionCaIssuersPresent implements JavaCRLLint {

    @Override
    public LintResult execute(X509CRL crl) {

        byte[] extensionValue = crl.getExtensionValue(Extension.authorityInfoAccess.getId());
        byte[] value = ASN1OctetString.getInstance(extensionValue).getOctets();
        AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(value);

        Predicate<AccessDescription> accessDescriptionIsCaIssuers = accessDescription -> accessDescription.getAccessMethod().equals(AccessDescription.id_ad_caIssuers);
        boolean caIssuersPresent = Arrays.stream(authorityInformationAccess.getAccessDescriptions()).anyMatch(accessDescriptionIsCaIssuers);

        if (caIssuersPresent) {
            return LintResult.of(Status.PASS);
        }

        return LintResult.of(Status.ERROR);

    }

    @Override
    public boolean checkApplies(X509CRL crl) {
        return CRLUtils.hasExtension(crl, Extension.authorityInfoAccess.getId());
    }

}
