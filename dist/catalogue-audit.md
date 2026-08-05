# Catalogue audit worksheet

Every clause reference this product can place in front of a client, with its provenance. **Anchored** means the ordinal has been confirmed against the published CERT-In guideline v2.0 (09.07.2025). **Provisional** means it was encoded from the table and has not been.

**26 of 101 clause references confirmed (25.74%).** The remainder are provisional. That number is published rather than rounded up, because a provisional ordinal presented as confirmed is the one defect that would discredit every assessment issued.

| Source | Confirmed | Total | % |
| --- | ---: | ---: | ---: |
| aibom | 3 | 16 | 18.75% |
| cbom | 1 | 20 | 5.0% |
| correlation | 5 | 5 | 100.0% |
| hbom | 1 | 15 | 6.67% |
| qbom | 1 | 10 | 10.0% |
| roadmap | 7 | 14 | 50.0% |
| sbom | 8 | 21 | 38.1% |

## Rows awaiting confirmation

| Source | Key | Element | Clause |
| --- | --- | --- | --- |
| sbom | component_name | Component Name | 4.2(1) |
| sbom | version | Version of the Component | 4.2(2) |
| sbom | description | Component Description | 4.2(3) |
| sbom | supplier_name | Supplier Name | 4.2(4) |
| sbom | origin | Origin / Source Repository | 4.2(6) |
| sbom | dependencies | Dependencies | 4.2(7) |
| sbom | checksums | Cryptographic Hash of the Component | 4.2(14) |
| sbom | executable_property | Executable Property | 4.2(15) |
| sbom | archive_property | Archive Property | 4.2(16) |
| sbom | structured_property | Structured Property | 4.2(17) |
| sbom | component_identifier | Unique Identifier of the Component | 4.2(18) |
| sbom | author_name | Author / Originator Name | 4.2(19) |
| sbom | timestamp | Timestamp | 4.2(20) |
| cbom | asset_type | Asset Type (algorithm | key | protocol | certificate) | s.8.4.1.3 |
| cbom | primitive | Cryptographic Primitive | s.8.4.1.4 |
| cbom | mode | Mode of Operation | s.8.4.1.5 |
| cbom | crypto_functions | Cryptographic Functions | s.8.4.1.6 |
| cbom | classical_security_level | Classical Security Level | s.8.4.1.7 |
| cbom | oid | Object Identifier (OID) | s.8.4.1.8 |
| cbom | key_id | Key Identifier | s.8.4.1.9 |
| cbom | key_state | Key State | s.8.4.1.10 |
| cbom | key_size | Key Size | s.8.4.1.11 |
| cbom | key_creation_date | Key Creation Date | s.8.4.1.12 |
| cbom | key_activation_date | Key Activation Date | s.8.4.1.13 |
| cbom | protocol_version | Protocol Version | s.8.4.2.1 |
| cbom | cipher_suites | Cipher Suites | s.8.4.2.2 |
| cbom | cert_subject | Certificate Subject | s.8.4.3.1 |
| cbom | cert_issuer | Certificate Issuer | s.8.4.3.2 |
| cbom | cert_validity | Certificate Validity Window | s.8.4.3.3 |
| cbom | cert_signature_algorithm | Certificate Signature Algorithm | s.8.4.3.4 |
| cbom | cert_format | Certificate Format | s.8.4.3.5 |
| cbom | deployment_context | Deployment Context | s.8.4.4.1 |
| qbom | model_name | Quantum System / Model Name | s.8.5.2 |
| qbom | vendor | Vendor | s.8.5.3 |
| qbom | origin | Country of Origin | s.8.5.4 |
| qbom | communication_protocol | Communication Protocol | s.8.5.5 |
| qbom | hardware | Hardware | s.8.5.6 |
| qbom | software_dependencies | Software Dependencies | s.8.5.7 |
| qbom | environmental_impact | Environmental Impact | s.8.5.8 |
| qbom | attestations | Attestations and Certifications | s.8.5.9 |
| qbom | deployment_exposure | Quantum Exposure of the Consuming Deployment | s.8.5.10 |
| aibom | model_name | Model Name | 9.3(1) |
| aibom | model_version | Model Version | 9.3(2) |
| aibom | model_type | Model Type / Architecture | 9.3(3) |
| aibom | developer | Model Developer | 9.3(4) |
| aibom | license | Model Licence | 9.3(5) |
| aibom | training_data_source | Training Data Source | 9.3(7) |
| aibom | data_preprocessing | Data Pre-processing | 9.3(8) |
| aibom | model_inputs | Model Inputs | 9.3(9) |
| aibom | model_outputs | Model Outputs | 9.3(10) |
| aibom | performance_metrics | Performance Metrics | 9.3(11) |
| aibom | evaluation_results | Evaluation Results | 9.3(12) |
| aibom | known_limitations | Known Limitations and Biases | 9.3(13) |
| aibom | hardware_requirements | Hardware / Compute Requirements | 9.3(14) |
| hbom | product_name | Product Name | 10.2(1) |
| hbom | model_number | Model Number | 10.2(2) |
| hbom | serial_number | Serial Number | 10.2(3) |
| hbom | manufacturer | Manufacturer | 10.2(4) |
| hbom | manufacturing_location | Manufacturing Location | 10.2(5) |
| hbom | manufacturing_date | Manufacturing Date | 10.2(6) |
| hbom | supplier_name | Supplier Name | 10.2(7) |
| hbom | supplier_location | Supplier Location | 10.2(8) |
| hbom | technology_node | Technology Node | 10.2(9) |
| hbom | warranty_ref | Warranty / AMC Reference | 10.2(10) |
| hbom | test_results | Test Results | 10.2(11) |
| hbom | compliance_declarations | Compliance Declarations | 10.2(12) |
| hbom | subcomponents | Subcomponents | 10.2(13) |
| hbom | deployment_criticality | Deployment Criticality and Siting | 10.2(14) |
| roadmap | pin_dependencies | Pin dependencies to exact versions | s.3.3.1.2 |
| roadmap | generate_sbom | Generate an SBOM for each product | s.3.3.1.3 |
| roadmap | vulnerability_scanning | Scan dependencies for known vulnerabilities | s.3.3.2.2 |
| roadmap | access_controls_on_boms | Apply access controls to stored BOMs | s.3.3.2.6 |
| roadmap | training | Train development teams on SSDLC practice | s.7.2.15 |
| roadmap | vex_history | Maintain a VEX history for disclosed vulnerabilities | s.3.3.3.1 |
| roadmap | continuous_monitoring | Monitor supplier conformance continuously | s.3.3.3.3 |

## Instrument findings

- **near collision** in hbom: 10.2(4) and s.10.2.4 differ only in notation

## What this document is not

It is not the audit. Re-deriving a clause from the published guideline is a person reading a PDF, and no instrument can do it. Anything here that claimed otherwise would be manufacturing the assurance it is meant to measure.
