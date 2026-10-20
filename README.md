![Tests](https://github.com/SigmaHQ/pySigma-pipeline-ocsf/actions/workflows/test.yml/badge.svg)
![Coverage Badge](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/andurin/a90f19ae7754f8b6cb0d9a3c9f624e53/raw/SigmaHQ-pySigma-pipeline-ocsf.json)
![Status](https://img.shields.io/badge/Status-pre--release-orange)

# pySigma ocsf Backend

This is the OCSF processing pipeline for pySigma. It provides the package `sigma.pipeline.ocsf` with the `ocsf_pipeline` function that returns a ProcessingPipeline object.

Currently the pipeline adds support for the following event types (Sigma logsource category to OCSF class mapping):

* application
* antivirus
* create_remote_thread
* create_stream_hash
* dns
* dns_query
* driver_load
* firewall
* file_access
* file_change
* file_delete
* file_event
* file_executable_detected
* file_rename
* image_load
* network_connection
* process_access
* process_creation
* process_tampering
* process_termination
* proxy
* registry_add
* registry_delete
* registry_event
* registry_rename
* registry_set
* sysmon_error
* webserver

This pipeline is currently maintained by:

* [Hendrik Baecker](https://github.com/andurin/)
