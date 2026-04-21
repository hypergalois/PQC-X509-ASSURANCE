package de.mtg.jzlint.lints.rfc;

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

/************************************************
 RFC 5280: 4.2.1.13
 When present, DistributionPointName SHOULD include at least one LDAP or HTTP URI.
 ************************************************/
@Lint(
        name = "w_distribution_point_missing_ldap_or_uri",
        description = "When present in the CRLDistributionPoints extension, DistributionPointName SHOULD include at least one LDAP or HTTP URI",
        citation = "RFC 5280: 4.2.1.13",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class DistributionPointMissingLdapOrUri implements JavaLint {

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

            DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
            if (distributionPointName.getType() == 0) {
                boolean match = startsWithCorrectPrefix(distributionPointName);
                if (!match) {
                    return LintResult.of(Status.WARN);
                }
            }
        }
        return LintResult.of(Status.PASS);
    }

    private boolean startsWithCorrectPrefix(DistributionPointName distributionPointName) {
        boolean startsWithCorrectPrefix = false;
        GeneralNames generalNames = (GeneralNames) distributionPointName.getName();
        GeneralName[] generalNamesArray = generalNames.getNames();
        for (GeneralName generalName : generalNamesArray) {
            if (generalName.getTagNo() == 6) {
                ASN1IA5String asn1IA5String = (ASN1IA5String) generalName.getName();
                if (asn1IA5String.getString().startsWith("http://") ||
                        asn1IA5String.getString().startsWith("ldap://")) {
                    startsWithCorrectPrefix = true;
                }
            }
        }
        return startsWithCorrectPrefix;
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasCRLDPExtension(certificate);
    }
}
