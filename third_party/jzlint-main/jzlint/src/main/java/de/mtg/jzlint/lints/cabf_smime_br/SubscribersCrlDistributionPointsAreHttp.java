package de.mtg.jzlint.lints.cabf_smime_br;

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

@Lint(
        name = "e_subscribers_crl_distribution_points_are_http",
        description = "cRLDistributionPoints SHALL have URI scheme HTTP.",
        citation = "7.1.2.3.b",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SubscribersCrlDistributionPointsAreHttp implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (!Utils.hasExtension(certificate, Extension.cRLDistributionPoints.getId())) {
            return LintResult.of(Status.ERROR, "SMIME certificate contains no HTTP URI schemes as CRL distribution points");
        }


        byte[] rawCRLDPs = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());

        CRLDistPoint cRLDPs;
        try {
            cRLDPs = CRLDistPoint.getInstance(ASN1OctetString.getInstance(rawCRLDPs).getOctets());
        } catch (Exception ex) {
            return LintResult.of(Status.FATAL);
        }

        DistributionPoint[] distributionPoints = cRLDPs.getDistributionPoints();

        int httpCount = 0;
        int crldpCount = 0;
        for (DistributionPoint distributionPoint : distributionPoints) {

            DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
            if (distributionPointName.getType() == 0) {
                GeneralNames generalNames = (GeneralNames) distributionPointName.getName();
                GeneralName[] generalNamesArray = generalNames.getNames();
                for (GeneralName generalName : generalNamesArray) {
                    crldpCount += 1;
                    if (generalName.getTagNo() == 6) {
                        ASN1IA5String asn1IA5String = (ASN1IA5String) generalName.getName();
                        if (asn1IA5String.getString().startsWith("http://") || asn1IA5String.getString().startsWith("https://")) {
                            httpCount += 1;
                        }
                    }
                }
            }
        }

        if ((SMIMEUtils.isMultipurposeSMIMECertificate(certificate) || SMIMEUtils.isStrictSMIMECertificate(certificate)) && httpCount != crldpCount) {
            return LintResult.of(Status.ERROR, "SMIME certificate contains invalid URI scheme in CRL distribution point");
        }

        if (SMIMEUtils.isLegacySMIMECertificate(certificate) && httpCount == 0) {
            return LintResult.of(Status.ERROR, "SMIME certificate contains no HTTP URI schemes as CRL distribution points");
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return SMIMEUtils.isSMIMEBRSubscriberCertificate(certificate);
    }

}
