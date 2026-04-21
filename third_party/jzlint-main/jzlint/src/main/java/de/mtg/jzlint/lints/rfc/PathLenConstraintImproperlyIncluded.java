package de.mtg.jzlint.lints.rfc;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

/******************************************************************
 RFC 5280: 4.2.1.9
 CAs MUST NOT include the pathLenConstraint field unless the cA
 boolean is asserted and the key usage extension asserts the
 keyCertSign bit.
 ******************************************************************/

@Lint(
        name = "e_path_len_constraint_improperly_included",
        description = "CAs MUST NOT include the pathLenConstraint field unless the CA boolean is asserted and the keyCertSign bit is set",
        citation = "RFC 5280: 4.2.1.9",
        source = Source.RFC5280,
        effectiveDate = EffectiveDate.RFC5280)
public class PathLenConstraintImproperlyIncluded implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawBasicConstraints = certificate.getExtensionValue(Extension.basicConstraints.getId());
        ASN1Sequence basicConstraints = ASN1Sequence.getInstance(ASN1OctetString.getInstance(rawBasicConstraints).getOctets());


        if (basicConstraints.size() == 0) {
            return LintResult.of(Status.PASS);
        }

        if (basicConstraints.size() == 1) {
            if (basicConstraints.getObjectAt(0) instanceof ASN1Boolean) {
                return LintResult.of(Status.PASS);
            } else {
                return LintResult.of(Status.ERROR);
            }
        }

        ASN1Boolean cA = (ASN1Boolean) basicConstraints.getObjectAt(0);

        if (!cA.isTrue()) {
            return LintResult.of(Status.ERROR);
        }

        if (!Utils.hasKeyUsageExtension(certificate)) {
            return LintResult.of(Status.ERROR);
        }

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());
        KeyUsage keyUsage = KeyUsage.getInstance(ASN1OctetString.getInstance(rawKeyUsage).getOctets());


        if (!keyUsage.hasUsages(KeyUsage.keyCertSign)) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.hasBasicConstraintsExtension(certificate);
    }
}
