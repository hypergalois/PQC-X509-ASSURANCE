package de.mtg.jzlint.lints.cabf_smime_br;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import de.mtg.jzlint.EffectiveDate;
import de.mtg.jzlint.JavaLint;
import de.mtg.jzlint.Lint;
import de.mtg.jzlint.LintResult;
import de.mtg.jzlint.Source;
import de.mtg.jzlint.Status;
import de.mtg.jzlint.utils.SMIMEUtils;
import de.mtg.jzlint.utils.Utils;

@Lint(
        name = "e_mailbox_validated_enforce_subject_field_restrictions",
        description = "SMIME certificates complying to mailbox validated profiles MAY only contain commonName, serialNumber or emailAddress attributes in the Subject DN",
        citation = "SMIME BRs: 7.1.4.2.3",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class MailboxValidatedEnforceSubjectFieldRestrictions implements JavaLint {

    private static final List<String> ALLOWED_OIDS = Arrays.asList(
            BCStyle.EmailAddress.getId(), X509ObjectIdentifiers.commonName.getId(), BCStyle.SERIALNUMBER.getId()
    );

    private static final Map<String, String> OID_NAMES = new HashMap<>();

    static {

        OID_NAMES.put(BCStyle.DC.getId(), "subject:domainComponent");
        OID_NAMES.put("1.3.6.1.4.1.311.60.2.1.1", "subject:jurisdictionLocality");
        OID_NAMES.put("1.3.6.1.4.1.311.60.2.1.2", "subject:jurisdictionProvince");
        OID_NAMES.put("1.3.6.1.4.1.311.60.2.1.3", "subject:jurisdictionCountry");
        OID_NAMES.put(BCStyle.SURNAME.getId(), "subject:surname");
        OID_NAMES.put(X509ObjectIdentifiers.countryName.getId(), "subject:countryName");
        OID_NAMES.put(X509ObjectIdentifiers.localityName.getId(), "subject:localityName");
        OID_NAMES.put(X509ObjectIdentifiers.stateOrProvinceName.getId(), "subject:stateOrProvinceName");
        OID_NAMES.put(BCStyle.STREET.getId(), "subject:streetAddress");
        OID_NAMES.put(X509ObjectIdentifiers.organization.getId(), "subject:organizationName");
        OID_NAMES.put(X509ObjectIdentifiers.organizationalUnitName.getId(), "subject:organizationalUnitName");
        OID_NAMES.put(BCStyle.T.getId(), "subject:title");
        OID_NAMES.put(BCStyle.POSTAL_CODE.getId(), "subject:postalCode");
        OID_NAMES.put(BCStyle.GIVENNAME.getId(), "subject:givenName");
        OID_NAMES.put(BCStyle.PSEUDONYM.getId(), "subject:pseudonym");
        OID_NAMES.put(BCStyle.ORGANIZATION_IDENTIFIER.getId(), "subject:organizationIdentifier");

    }

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {
            List<String> dnOIDs = Utils.getAllAttributeTypesInSubject(certificate);


            Optional<String> forbiddenOID = dnOIDs.stream().filter(oid -> !ALLOWED_OIDS.contains(oid)).findAny();

            if (forbiddenOID.isPresent()) {
                String oid = forbiddenOID.get();

                if (OID_NAMES.containsKey(oid)) {
                    return LintResult.of(Status.ERROR,
                            String.format("subject DN contains forbidden field: %s (%s)", OID_NAMES.get(oid), forbiddenOID.get()));
                } else {
                    return LintResult.of(Status.ERROR, String.format("subject DN contains forbidden field: %s", oid));
                }

            }
        } catch (CertificateEncodingException ex) {
            return LintResult.of(Status.FATAL);
        }
        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {
        return SMIMEUtils.isMailboxValidatedCertificate(certificate) && Utils.isSubscriberCert(certificate);
    }

}
