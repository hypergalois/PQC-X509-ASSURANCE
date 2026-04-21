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

/***********************************************
 BRs: 7.1.2.2c
 This extension SHOULD be present. It MUST NOT be marked critical.
 It SHOULD contain the HTTP URL of the Issuing CA’s certificate (accessMethod =
 1.3.6.1.5.5.7.48.2). It MAY contain the HTTP URL of the Issuing CA’s OCSP responder
 (accessMethod = 1.3.6.1.5.5.7.48.1).
 ************************************************/

@Lint(
        name = "w_sub_ca_aia_does_not_contain_issuing_ca_url",
        description = "Subordinate CA Certificate: authorityInformationAccess SHOULD also contain the HTTP URL of the Issuing CA's certificate.",
        citation = "BRs: 7.1.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class SubCaAiaDoesNotContainIssuingCaUrl implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {
        byte[] aiaValue = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());

        if (aiaValue == null) {
            return LintResult.of(Status.WARN);
        }

        AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(ASN1OctetString.getInstance(aiaValue).getOctets());

        AccessDescription[] accessDescriptions = aia.getAccessDescriptions();

        for (AccessDescription accessDescription : accessDescriptions) {
            if (AccessDescription.id_ad_caIssuers.equals(accessDescription.getAccessMethod())) {
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
        return Utils.isCA(certificate) && !Utils.isRootCA(certificate);
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
