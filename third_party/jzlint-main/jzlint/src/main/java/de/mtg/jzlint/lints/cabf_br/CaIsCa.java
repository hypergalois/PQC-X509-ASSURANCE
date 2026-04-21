package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_ca_is_ca",
        description = "Root and Sub CA Certificate: The CA field MUST be set to true.",
        citation = "BRs: 7.1.2.1, BRs: 7.1.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class CaIsCa implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawBasicConstraints = certificate.getExtensionValue(Extension.basicConstraints.getId());

        BasicConstraints basicConstraints = BasicConstraints.getInstance(ASN1OctetString.getInstance(rawBasicConstraints).getOctets());

        if (basicConstraints.isCA()) {
            return LintResult.of(Status.PASS);
        }

        return LintResult.of(Status.ERROR);

    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        if (!Utils.hasKeyUsageExtension(certificate)) {
            return false;
        }

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());

        KeyUsage keyUsage = KeyUsage.getInstance(ASN1OctetString.getInstance(rawKeyUsage).getOctets());

        if (!keyUsage.hasUsages(KeyUsage.keyCertSign)) {
            return false;
        }

        return Utils.hasBasicConstraintsExtension(certificate);

    }


}
