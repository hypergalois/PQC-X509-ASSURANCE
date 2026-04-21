package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/********************************************************************
 The cRLDistributionPoints extension is a SEQUENCE of
 DistributionPoint.  A DistributionPoint consists of three fields,
 each of which is optional: distributionPoint, reasons, and cRLIssuer.
 While each of these fields is optional, a DistributionPoint MUST NOT
 consist of only the reasons field; either distributionPoint or
 cRLIssuer MUST be present.  If the certificate issuer is not the CRL
 issuer, then the cRLIssuer field MUST be present and contain the Name
 of the CRL issuer.  If the certificate issuer is also the CRL issuer,
 then conforming CAs MUST omit the cRLIssuer field and MUST include
 the distributionPoint field.
 ********************************************************************/
@Lint(
        name = "e_distribution_point_incomplete",
        description = "A DistributionPoint from the CRLDistributionPoints extension MUST NOT consist of only the reasons field; either distributionPoint or CRLIssuer must be present",
        citation = "RFC 5280: 4.2.1.13",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC3280)
public class DistributionPointIncomplete implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawCRLDPs = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());

        if (rawCRLDPs == null) {
            return LintResult.of(Status.FATAL);
        }

        CRLDistPoint cRLDPs;
        try {
            cRLDPs = CRLDistPoint.getInstance(ASN1OctetString.getInstance(rawCRLDPs).getOctets());
        } catch (Exception ex) {
            return LintResult.of(Status.FATAL);
        }

        DistributionPoint[] distributionPoints = cRLDPs.getDistributionPoints();

        for (DistributionPoint distributionPoint : distributionPoints) {
            if (distributionPoint.getReasons() != null && distributionPoint.getCRLIssuer() == null && distributionPoint.getDistributionPoint() == null) {
                return LintResult.of(Status.ERROR);
            }
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasCRLDPExtension(certificate);
    }
}
