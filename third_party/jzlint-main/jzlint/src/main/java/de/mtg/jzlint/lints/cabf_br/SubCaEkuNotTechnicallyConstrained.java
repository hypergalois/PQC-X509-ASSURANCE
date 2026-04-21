package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "n_sub_ca_eku_not_technically_constrained",
        description = "Subordinate CA extkeyUsage, either id-kp-serverAuth or id-kp-clientAuth or both values MUST be present to be technically constrained.",
        citation = "BRs: 7.1.2.2",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABV116Date)
public class SubCaEkuNotTechnicallyConstrained implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawExtendedKeyUsage = certificate.getExtensionValue(Extension.extendedKeyUsage.getId());
        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(ASN1OctetString.getInstance(rawExtendedKeyUsage).getOctets());
        if (extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth) ||
                extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_clientAuth)) {
            return LintResult.of(Status.PASS);
        }
        return LintResult.of(Status.NOTICE);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isSubCA(certificate) && Utils.hasExtendedKeyUsageExtension(certificate);
    }

}
