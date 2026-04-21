package de.mtg.jzlint.lints.cabf_smime_br;

import java.security.cert.X509Certificate;

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
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

/************************************************************************
 BRs: 7.1.2.3c
 CA Certificate Authority Information Access
 The authorityInformationAccess extension MAY contain one or more accessMethod
 values for each of the following types:

 id-ad-ocsp        specifies the URI of the Issuing CA's OCSP responder.
 id-ad-caIssuers   specifies the URI of the Issuing CA's Certificate.

 For Legacy: When provided, at least one accessMethod SHALL have the URI scheme HTTP. Other schemes (LDAP, FTP, ...) MAY be present.
 *************************************************************************/

@Lint(
        name = "e_smime_legacy_aia_shall_have_one_http",
        description = "SMIME Legacy certificates authorityInformationAccess When provided, at least one accessMethod SHALL have the URI scheme HTTP. Other schemes (LDAP, FTP, ...) MAY be present.",
        citation = "BRs: 7.1.2.3c",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SmimeLegacyAiaShallHaveOneHttp implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] aiaValue = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());

        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ASN1OctetString.getInstance(aiaValue).getOctets());

        AccessDescription[] accessDescriptions = aia.getAccessDescriptions();

        boolean atLeastOneHttpInOCSP = false;
        boolean atLeastOneHttpInCaIssuers = false;

        for (AccessDescription accessDescription : accessDescriptions) {
            GeneralName accessLocation = accessDescription.getAccessLocation();
            if (AccessDescription.id_ad_ocsp.equals(accessDescription.getAccessMethod())) {
                if (startsWithCorrectPrefix(accessLocation)) {
                    atLeastOneHttpInOCSP = true;
                }
            } else if (AccessDescription.id_ad_caIssuers.equals(accessDescription.getAccessMethod())) {
                if (startsWithCorrectPrefix(accessLocation)) {
                    atLeastOneHttpInCaIssuers = true;
                }
            }
        }

        if (!atLeastOneHttpInOCSP) {
            return LintResult.of(Status.ERROR, "at least one id-ad-ocsp accessMethod MUST have the URI scheme HTTP");
        }

        if (!atLeastOneHttpInCaIssuers) {
            return LintResult.of(Status.ERROR, "at least one id-ad-caIssuers accessMethod MUST have the URI scheme HTTP");
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasAuthorityInformationAccessExtension(certificate) &&
                Utils.isSubscriberCert(certificate) &&
                SMIMEUtils.isLegacySMIMECertificate(certificate);
    }

    private boolean startsWithCorrectPrefix(GeneralName generalName) {
        boolean startsWithCorrectPrefix = false;

        if (generalName.getTagNo() == 6) {
            ASN1IA5String asn1IA5String = (ASN1IA5String) generalName.getName();
            if (asn1IA5String.getString().startsWith("http://") || asn1IA5String.getString().startsWith("https://")) {
                startsWithCorrectPrefix = true;
            }
        }

        return startsWithCorrectPrefix;
    }

}
