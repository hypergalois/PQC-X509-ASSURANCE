package de.mtg.jlint.lints.smime;

import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;

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
 * b. cRLDistributionPoints (SHALL be present)
 * This extension SHOULD NOT be marked critical. It SHALL contain at least one
 * distributionPoint whose fullName value includes a GeneralName of type
 * uniformResourceIdentifier that includes a URI where the Issuing CA’s CRL can be
 * retrieved.
 */
@Lint(
        name = "e_smime_crldp_contains_uri_fullname",
        description = "Check if a subscriber certificate contains at least one distributionPoint whose fullName " +
                "value includes a GeneralName of type uniformResourceIdentifier",
        citation = "SMIME BR 7.1.2.3a",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SmimeCrldpContainsUriFullname implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawCRLDPs = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());

        CRLDistPoint cRLDPs;
        try {
            cRLDPs = CRLDistPoint.getInstance(ASN1OctetString.getInstance(rawCRLDPs).getOctets());
        } catch (Exception ex) {
            return LintResult.of(Status.FATAL);
        }

        DistributionPoint[] distributionPoints = cRLDPs.getDistributionPoints();

        for (DistributionPoint distributionPoint : distributionPoints) {
            DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
            if (distributionPointName.getType() != 0) {
                continue;
            }

            GeneralNames generalNames = (GeneralNames) distributionPointName.getName();
            GeneralName[] generalNamesArray = generalNames.getNames();
            for (GeneralName generalName : generalNamesArray) {
                if (generalName.getTagNo() != 6) {
                    continue;
                }
                ASN1IA5String asn1IA5String = (ASN1IA5String) generalName.getName();
                try {
                    new URL(asn1IA5String.getString()).toURI();
                    return LintResult.of(Status.PASS);
                } catch (URISyntaxException | MalformedURLException ex) {
                    LintResult.of(Status.FATAL);
                }
            }
        }
        return LintResult.of(Status.ERROR);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return SMIMEUtils.isSMIMEBRSubscriberCertificate(certificate) && Utils.hasCRLDPExtension(certificate);
    }

}