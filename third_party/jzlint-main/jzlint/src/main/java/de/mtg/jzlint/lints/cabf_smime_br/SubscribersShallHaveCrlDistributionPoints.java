package de.mtg.jzlint.lints.cabf_smime_br;

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
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_subscribers_shall_have_crl_distribution_points",
        description = "cRLDistributionPoints SHALL be present.",
        citation = "7.1.2.3.b",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class SubscribersShallHaveCrlDistributionPoints implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (!Utils.hasCRLDPExtension(certificate)) {
            return LintResult.of(Status.ERROR, "SMIME certificate contains zero CRL distribution points");
        }

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

        if (distributionPoints == null || distributionPoints.length == 0) {
            return LintResult.of(Status.ERROR, "SMIME certificate contains zero CRL distribution points");
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubscriberCert(certificate) && SMIMEUtils.isSMIMEBRCertificate(certificate);
    }

}
