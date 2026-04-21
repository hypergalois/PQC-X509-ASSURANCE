package de.mtg.jzlint.lints.cabf_br;

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
import de.mtg.jzlint.utils.Utils;

/*******************************************************************************************************
 BRs: 7.1.2.3
 cRLDistributionPoints
 This extension MAY be present. If present, it MUST NOT be marked critical, and it MUST contain the HTTP
 URL of the CA’s CRL service.
 *******************************************************************************************************/

@Lint(
        name = "e_sub_cert_crl_distribution_points_does_not_contain_url",
        description = "Subscriber certificate cRLDistributionPoints extension must contain the HTTP URL of the CA’s CRL service",
        citation = "BRs: 7.1.2.3",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class SubCertCrlDistributionPointsDoesNotContainUrl implements JavaLint {

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
            if (distributionPointName.getType() == 0) {
                boolean match = startsWithCorrectPrefix(distributionPointName);
                if (!match) {
                    return LintResult.of(Status.ERROR);
                }
            }
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasCRLDPExtension(certificate);
    }

    private boolean startsWithCorrectPrefix(DistributionPointName distributionPointName) {
        boolean startsWithCorrectPrefix = false;
        GeneralNames generalNames = (GeneralNames) distributionPointName.getName();
        GeneralName[] generalNamesArray = generalNames.getNames();
        for (GeneralName generalName : generalNamesArray) {
            if (generalName.getTagNo() == 6) {
                ASN1IA5String asn1IA5String = (ASN1IA5String) generalName.getName();
                if (asn1IA5String.getString().startsWith("http://")) {
                    startsWithCorrectPrefix = true;
                }
            }
        }
        return startsWithCorrectPrefix;
    }
}
