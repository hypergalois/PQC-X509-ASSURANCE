package de.mtg.jzlint.lints.cabf_smime_br;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.time.ZoneId;
import java.time.ZonedDateTime;

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
import de.mtg.jzlint.utils.GTLDUtils;
import de.mtg.jzlint.utils.IPUtils;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;


/************************************************************************
 BRs: 7.1.2.3c
 CA Certificate Authority Information Access
 The authorityInformationAccess extension MAY contain one or more accessMethod
 values for each of the following types:

 id-ad-ocsp        specifies the URI of the Issuing CA's OCSP responder.
 id-ad-caIssuers   specifies the URI of the Issuing CA's Certificate.
 *************************************************************************/

@Lint(
        name = "w_smime_aia_contains_internal_names",
        description = "SMIME certificates authorityInformationAccess. Internal domain names should not be included.",
        citation = "BRs: 7.1.2.3c",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SmimeAiaContainsInternalNames implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] aiaValue = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());

        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ASN1OctetString.getInstance(aiaValue).getOctets());

        AccessDescription[] accessDescriptions = aia.getAccessDescriptions();

        for (AccessDescription accessDescription : accessDescriptions) {
            GeneralName accessLocation = accessDescription.getAccessLocation();
            if (accessLocation.getTagNo() == 6) {
                ASN1IA5String asn1IA5String = (ASN1IA5String) accessLocation.getName();

                try {
                    URI uri = new URI(asn1IA5String.getString());

                    String host = uri.getHost();

                    if (IPUtils.isIP(host)) {
                        continue;
                    }

                    if (GTLDUtils.gtldDidnotExist(uri.getHost(), ZonedDateTime.now(ZoneId.of("UTC")))) {
                        return LintResult.of(Status.WARN);
                    }
                } catch (URISyntaxException | ParseException ex) {
                    throw new RuntimeException(ex);
                }
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasAuthorityInformationAccessExtension(certificate) &&
                Utils.isSubscriberCert(certificate) && SMIMEUtils.isSMIMEBRCertificate(certificate);
    }

}
