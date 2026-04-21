package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/************************************************
 RFC 5280: 4.2.2.1
 An authorityInfoAccess extension may include multiple instances of
 the id-ad-caIssuers accessMethod.  The different instances may
 specify different methods for accessing the same information or may
 point to different information.  When the id-ad-caIssuers
 accessMethod is used, at least one instance SHOULD specify an
 accessLocation that is an HTTP [RFC2616] or LDAP [RFC4516] URI.
 ************************************************/
@Lint(
        name = "w_ext_aia_access_location_missing",
        description = "When the id-ad-caIssuers accessMethod is used, at least one instance SHOULD specify an accessLocation that is an HTTP or LDAP URI",
        citation = "RFC 5280: 4.2.2.1",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class ExtAiaAccessLocationMissing implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        AccessDescription[] accessDescriptions = getAccessDescriptions(certificate);

        for (AccessDescription accessDescription : accessDescriptions) {
            if (org.bouncycastle.asn1.x509.AccessDescription.id_ad_caIssuers.getId().equalsIgnoreCase(accessDescription.getAccessMethod().getId())) {
                GeneralName accessLocation = accessDescription.getAccessLocation();
                if (startsWithCorrectPrefix(accessLocation)) {
                    return LintResult.of(Status.PASS);
                }
            }
        }

        return LintResult.of(Status.WARN);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        if (!Utils.hasAuthorityInformationAccessExtension(certificate)) {
            return false;
        }
        AccessDescription[] accessDescriptions = getAccessDescriptions(certificate);
        return Arrays.stream(accessDescriptions).anyMatch(accessDescription -> AccessDescription.id_ad_caIssuers.getId().equalsIgnoreCase(accessDescription.getAccessMethod().getId()));

    }

    private AccessDescription[] getAccessDescriptions(X509Certificate certificate) {
        byte[] aiaValue = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());

        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ASN1OctetString.getInstance(aiaValue).getOctets());
        return aia.getAccessDescriptions();
    }

    private boolean startsWithCorrectPrefix(GeneralName generalName) {
        boolean startsWithCorrectPrefix = false;

        if (generalName.getTagNo() == 6) {
            ASN1IA5String asn1IA5String = (ASN1IA5String) generalName.getName();
            if (asn1IA5String.getString().startsWith("http://") || asn1IA5String.getString().startsWith("ldap://")) {
                startsWithCorrectPrefix = true;
            }
        }

        return startsWithCorrectPrefix;
    }

}
