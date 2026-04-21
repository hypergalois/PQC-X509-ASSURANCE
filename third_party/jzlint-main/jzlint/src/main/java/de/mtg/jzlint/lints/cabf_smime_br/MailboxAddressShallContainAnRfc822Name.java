package de.mtg.jzlint.lints.cabf_smime_br;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
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
        name = "e_mailbox_address_shall_contain_an_rfc822_name",
        description = "All Mailbox Addresses in the subject field or entries of type dirName of this extension SHALL be repeated as rfc822Name or otherName values of type id-on-SmtpUTF8Mailbox in this extension",
        citation = "SMIME BRs: 7.1.4.2.1",
        source = Source.CABF_SMIME_BASELINE_REQUIREMENTS,
        effectiveDate = EffectiveDate.SMIME_BR_1_0_DATE)
public class MailboxAddressShallContainAnRfc822Name implements JavaLint {

    @Override
    public LintResult execute(X509Certificate certificate) {

        try {

            List<String> subjectEmails = getMailboxAddresses(certificate);

            List<String> sanEmails = Utils.getEmails(certificate);
            sanEmails.addAll(SMIMEUtils.getSmtpUTF8Mailboxes(certificate));

            for (String subjectEmail : subjectEmails) {
                if (!sanEmails.contains(subjectEmail)) {
                    return LintResult.of(Status.ERROR,
                            "all certificate mailbox addresses must be present in san:emailAddresses or san:otherNames in addition to any other field they may appear");
                }
            }

        } catch (IOException ex) {
            return LintResult.of(Status.FATAL);
        }


        return LintResult.of(Status.PASS);
    }

    @Override
    public boolean checkApplies(X509Certificate certificate) {

        if (!SMIMEUtils.isSMIMEBRSubscriberCertificate(certificate)) {
            return false;
        }

        List<String> mailboxAddresses = getMailboxAddresses(certificate);

        return !mailboxAddresses.isEmpty();

    }

    private List<String> getMailboxAddresses(X509Certificate certificate) {
        List<String> mailboxAddresses = getMailboxAddressesFromName(certificate.getSubjectX500Principal().getEncoded(),
                SMIMEUtils.isMailboxValidatedCertificate(certificate));

        byte[] rawSAN = certificate.getExtensionValue(Extension.subjectAlternativeName.getId());

        try {
            if (rawSAN != null) {
                GeneralNames generalNames = GeneralNames.getInstance(((ASN1OctetString) ASN1Primitive.fromByteArray(rawSAN)).getOctets());
                GeneralName[] names = generalNames.getNames();
                List<ASN1Encodable> generalNameList = new ArrayList<>();
                Arrays.stream(names).filter(generalName -> generalName.getTagNo() == 4).map(g -> g.getName()).forEach(generalNameList::add);
                for (ASN1Encodable encodable : generalNameList) {
                    List<String> mailboxAddressesFromName = getMailboxAddressesFromName(encodable.toASN1Primitive().getEncoded(), false);
                    mailboxAddresses.addAll(mailboxAddressesFromName);
                }
            }
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
        return mailboxAddresses;
    }

    private List<String> getMailboxAddressesFromName(byte[] encodedName, boolean includeCN) {
        List<String> emails = new ArrayList<>();

        List<AttributeTypeAndValue> commonName = Utils.getNameComponent(X509ObjectIdentifiers.commonName.getId(), encodedName);

        if (includeCN) {
            for (AttributeTypeAndValue attributeTypeAndValue : commonName) {
                String email = attributeTypeAndValue.getValue().toString();
                if (SMIMEUtils.isValidEmailAddress(email)) {
                    emails.add(email);
                }
            }
        }

        List<AttributeTypeAndValue> dnEmails = Utils.getNameComponent(BCStyle.EmailAddress.getId(), encodedName);
        for (AttributeTypeAndValue attributeTypeAndValue : dnEmails) {
            String email = attributeTypeAndValue.getValue().toString();
            if (SMIMEUtils.isValidEmailAddress(email)) {
                emails.add(email);
            }
        }
        return emails;
    }

}
