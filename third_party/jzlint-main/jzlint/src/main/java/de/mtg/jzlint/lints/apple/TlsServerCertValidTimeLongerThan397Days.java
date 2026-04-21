package de.mtg.jzlint.lints.apple;

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
import de.mtg.jzlint.utils.DateUtils;
import de.mtg.jzlint.utils.Utils;


@Lint(
        name = "w_tls_server_cert_valid_time_longer_than_397_days",
        description = "TLS server certificates issued on or after September 1, 2020 00:00 GMT/UTC should not have a validity period greater than 397 days",
        citation = "https://support.apple.com/en-us/HT211025",
        source = Source.APPLE_ROOT_STORE_POLICY,
        effectiveDate = EffectiveDate.AppleReducedLifetimeDate)
public class TlsServerCertValidTimeLongerThan397Days implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        if (DateUtils.isIssuedOnOrAfter(certificate, EffectiveDate.AppleReducedLifetimeDate.getZonedDateTime())) {

            if (DateUtils.getValidityInDays(certificate) > 397) {
                return LintResult.of(Status.WARN, "Apple recommends that certificates be issued with a maximum validity of 397 days.");
            }
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        if (Utils.isCA(certificate)) {
            return false;
        }

        byte[] rawEKU = certificate.getExtensionValue(Extension.extendedKeyUsage.getId());

        if (rawEKU == null) {
            return true;
        }

        ExtendedKeyUsage extendedKeyUsage = ExtendedKeyUsage.getInstance(ASN1OctetString.getInstance(rawEKU).getOctets());

        if (extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.anyExtendedKeyUsage) ||
                extendedKeyUsage.hasKeyPurposeId(KeyPurposeId.id_kp_serverAuth)) {
            return true;
        }
        return false;
    }

}
