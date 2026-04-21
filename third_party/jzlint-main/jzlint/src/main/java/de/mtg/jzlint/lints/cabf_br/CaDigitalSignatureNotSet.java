package de.mtg.jzlint.lints.cabf_br;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.Utils;


/************************************************
 BRs: 7.1.2.1b: Root CA Certificate keyUsage
 This extension MUST be present and MUST be marked critical. Bit positions for keyCertSign and cRLSign MUST be set.
 If the Root CA Private Key is used for signing OCSP responses, then the digitalSignature bit MUST be set.
 BRs: 7.1.2.2e: Subordinate CA Certificate keyUsage
 This extension MUST be present and MUST be marked critical. Bit positions for keyCertSign and cRLSign MUST be set.
 If the Root CA Private Key is used for signing OCSP responses, then the digitalSignature bit MUST be set.
 ************************************************/


@Lint(
        name = "n_ca_digital_signature_not_set",
        description = "Root and Subordinate CA Certificates that wish to use their private key for signing OCSP responses will not be able to without their digital signature set",
        citation = "BRs: 7.1.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class CaDigitalSignatureNotSet implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());

        KeyUsage keyUsage = KeyUsage.getInstance(ASN1OctetString.getInstance(rawKeyUsage).getOctets());

        if (!keyUsage.hasUsages(KeyUsage.digitalSignature)) {
            return LintResult.of(Status.NOTICE);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isCA(certificate) && Utils.hasExtension(certificate, Extension.keyUsage.getId());
    }


}
