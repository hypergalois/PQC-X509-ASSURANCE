package de.mtg.jzlint.lints.cabf_br;

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
import de.mtg.jzlint.utils.Utils;

/************************************************************************
 BRs: 7.1.2.3
 cRLDistributionPoints
 This extension MAY be present. If present, it MUST NOT be marked critical, and it MUST contain the
 HTTP URL of the CA’s CRL service.
 *************************************************************************/

@Lint(
        name = "w_sub_cert_aia_does_not_contain_issuing_ca_url",
        description = "Subscriber certificates authorityInformationAccess extension should contain the HTTP URL of the issuing CA’s certificate",
        citation = "BRs: 7.1.2.3",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class SubCertAiaDoesNotContainIssuingCaUrl implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        byte[] aiaValue = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());

        if (aiaValue == null) {
            return LintResult.of(Status.WARN);
        }

        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ASN1OctetString.getInstance(aiaValue).getOctets());

        AccessDescription[] accessDescriptions = aia.getAccessDescriptions();

        for (AccessDescription accessDescription : accessDescriptions) {
            if (org.bouncycastle.asn1.x509.AccessDescription.id_ad_caIssuers.equals(accessDescription.getAccessMethod())) {
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
        return Utils.isSubscriberCert(certificate);
    }

    private boolean startsWithCorrectPrefix(GeneralName generalName) {
        boolean startsWithCorrectPrefix = false;

        if (generalName.getTagNo() == 6) {
            ASN1IA5String asn1IA5String = (ASN1IA5String) generalName.getName();
            if (asn1IA5String.getString().startsWith("http://")) {
                startsWithCorrectPrefix = true;
            }
        }

        return startsWithCorrectPrefix;
    }

}
