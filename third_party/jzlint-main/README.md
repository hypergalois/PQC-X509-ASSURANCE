# JZLint

JZLint is a port of [ZLint](https://github.com/zmap/zlint) in Java.

* To support differential testing between Go and Java libraries that process certificates and CRLs.
* To provide a more direct integration in the Java ecosystem.
* To implement lints additionally to ZLint.

JZLint is compatible with Java 17.

## Lints

### Additional Lints

JZLint implement several lints additionally to ZLint. This is the list of additional lints:

* e_crl_entry_reason_code_ext_not_critical
* e_crl_entry_reason_code_unspecified
* e_subject_one_ava_instance
* e_subject_rdn_one_ava
* e_crl_aia_extension_ca_issuers_present
* e_crl_aia_extension_non_critical
* e_crl_aki_extension_mandatory
* e_crl_crl_number_extension_mandatory
* e_crl_version_value_is_two
* e_crl_with_extensions_version_value_is_two
* e_crl_with_extensions_version_value_mandatory
* e_issuer_common_name_max_length
* e_issuer_dn_serial_number_max_length
* e_issuer_email_max_length
* e_issuer_given_name_max_length
* w_issuer_given_name_recommended_max_length
* e_issuer_organizational_unit_name_max_length
* e_issuer_organization_name_max_length
* e_issuer_postal_code_max_length
* e_issuer_state_name_max_length
* e_issuer_street_address_max_length
* e_issuer_surname_max_length
* w_issuer_surname_recommended_max_length
* e_ocsp_contains_reasoncode
* e_ocsp_sign_sha1_prohibited
* e_ocsp_lint_correct_response_status
* e_ocsp_lint_correct_version
* e_ocsp_lint_response_well_formed
* e_ocsp_lint_version_default_value_encoded
* e_crl_issuer_invalid_signature
* e_crl_issuer_lint_key_identifier_mismatch
* e_issuer_invalid_signature
* e_issuer_lint_key_identifier_mismatch
* e_smime_aia_extension_critical
* w_smime_aia_present
* e_smime_certificate_policies_contain_explicittext_unotice
* e_smime_certificate_policies_contain_http_url_qualifier
* e_smime_certificate_policies_contain_reserved_policy_oid
* w_smime_certificate_policies_extension_critical
* e_smime_certificate_policies_present
* w_smime_crldistributionpoints_extension_critical
* e_smime_crldp_contains_uri_fullname
* e_smime_ski_extension_critical
* e_smime_subjectkeyidentifier_present
* e_subject_rdns_correct_encoding
* e_subject_rdns_maximum_length

Additional lints are located in the subproject jlint-ext.

Lints for OCSP responses are located in the subproject jlint-ocsp.

Lints that have the issuer of the certificate as an additional input are located in the subproject jlint-issuer.

### Missing Lints

Following lints of ZLint are not implemented yet:

1. e_ext_ian_uri_host_not_fqdn_or_ip
2. e_ext_san_uri_host_not_fqdn_or_ip
3. e_name_constraint_not_fqdn
4. e_ext_tor_service_descriptor_hash_invalid
5. e_dnsname_contains_bare_iana_suffix
6. n_dnsname_wildcard_left_of_public_suffix
7. e_ext_nc_intersects_reserved_ip
8. e_ext_san_contains_reserved_ip
9. e_ext_tor_service_descriptor_hash_invalid
10. n_contains_redacted_dnsname
11. w_subject_contains_malformed_arpa_ip
12. e_subject_contains_reserved_arpa_ip
13. e_subject_contains_reserved_ip
14. e_san_dns_name_onion_not_ev_cert
15. e_utc_time_not_in_zulu
16. e_san_dns_name_onion_invalid
17. e_utc_time_does_not_include_seconds
18. e_international_dns_name_not_nfc
19. e_generalized_time_does_not_include_seconds

