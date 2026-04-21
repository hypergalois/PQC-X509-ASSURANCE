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
 BRs: 7.1.2.1b
 This extension MUST be present and MUST be marked critical. Bit positions for keyCertSign and cRLSign MUST be set.
 If the Root CA Private Key is used for signing OCSP responses, then the digitalSignature bit MUST be set.
 ************************************************/

@Lint(
        name = "e_ca_key_cert_sign_not_set",
        description = "Root CA Certificate: Bit positions for keyCertSign and cRLSign MUST be set.",
        citation = "BRs: 7.1.2.1",
        source = Source.CABF_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.CABEffectiveDate)
public class CaKeyCertSignNotSet implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        byte[] rawKeyUsage = certificate.getExtensionValue(Extension.keyUsage.getId());

        KeyUsage keyUsage = KeyUsage.getInstance(ASN1OctetString.getInstance(rawKeyUsage).getOctets());

        if (!keyUsage.hasUsages(KeyUsage.keyCertSign)) {
            return LintResult.of(Status.ERROR);
        }

        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return Utils.isCA(certificate) && Utils.hasExtension(certificate, Extension.keyUsage.getId());
    }


}
