from sigma.pipelines.base import Pipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
    ConvertTypeTransformation,
    ReplaceStringTransformation,
)

from sigma.processing.conditions import (
    LogsourceCondition,
    IncludeFieldCondition,
    RuleContainsFieldCondition,
    RuleContainsDetectionItemCondition,
)
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

# Contains windows mappings in form of:
# {product: {service: {eventid: {field: value}}}}
ocsf_windows_eventid_mapping = {
    "windows": {
        "security": {
            4624: {"type_uid": 3002001},
            4625: {"type_uid": 3002001},
            4697: {"type_uid": 20100401},
        },
        "system": {
            7045: {"type_uid": 20100401},
        },
    }
}

ocsf_generic_logsource_category_mapping = {  # map generic Sigma log source categories to OCSF Categories and Activities
    "application": {
        "class_uid": 6002,
        "category_uid": 6,
    },
    "antivirus": {
        "class_uid": 2004,
        "category_uid": 2,
    },
    # "clipboard_capture": 24,
    "create_remote_thread": {"type_uid": 100704},
    "create_stream_hash": {"type_uid": 100103},
    "dns": {"class_uid": 4003},
    "dns_query": {"class_uid": 4003},
    "driver_load": {"type_uid": 100201},
    "firewall": {"class_uid": 4001},
    "file_access": {"type_uid": 100114},
    "file_change": {"type_uid": 100103},
    "file_delete": {"type_uid": 100104},
    "file_event": {"type_uid": 100101},
    "file_executable_detected": {"type_uid": 100101},
    "file_rename": {"type_uid": 100105},
    "image_load": {"class_uid": 1007},  # module loads are recognized by module.file.path, see below
    "network_connection": {"class_uid": 4001},
    # "pipe_created": [17, 18],
    "process_access": {"type_uid": 100703},
    "process_creation": {"type_uid": 100701},
    "process_tampering": {"type_uid": 100799},
    "process_termination": {"type_uid": 100702},
    # "raw_access_thread": 9,
    "registry_add": {"type_uid": 20100101},
    "registry_delete": {"type_uid": 20100104},
    "registry_event": {
        "class_uid": 201001,
    },
    "registry_rename": {"type_uid": 20100105},
    "registry_set": {"type_uid": 20100202},
    "sysmon_error": {"type_uid": 600801},
    "ps_script": {"type_uid": 100901},
    "ps_module": {"type_uid": 100901},
    # "sysmon_status": [4, 16],
    # "wmi_event": [19, 20, 21],
    "proxy": {"class_uid": 4002},
    "webserver": {"class_uid": 4002},
}


@Pipeline  # type: ignore
def ocsf_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="OCSF pipeline",
        allowed_backends=frozenset(),  # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=20,  # The priority defines the order pipelines are applied. See documentation for common values.
        items=[
            ProcessingItem(  # Process Activity has no module load activity: require a loaded module
                identifier="ocsf_image_load_module_file_path",
                transformation=AddConditionTransformation(
                    {"module.file.path": None}, negated=True
                ),
                rule_conditions=[LogsourceCondition(category="image_load")],
            )
        ]
        + [
            ProcessingItem(
                identifier=f"ocsf_{log_source}_{field}",
                transformation=AddConditionTransformation(
                    {
                        field: value,
                    }
                ),
                rule_conditions=[LogsourceCondition(category=log_source)],
            )
            for log_source, mappeddata in ocsf_generic_logsource_category_mapping.items()
            for field, value in sorted(mappeddata.items())
        ]
        # Create processing items for Windows according to Service and EventID
        + [
            ProcessingItem(
                identifier=f"ocsf_{mappedproduct}_{mappedservice}_{mappedeventid}_{field}",
                transformation=AddConditionTransformation(
                    {
                        field: value,
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(product=mappedproduct),
                    LogsourceCondition(service=mappedservice),
                    RuleContainsFieldCondition(field="EventID"),
                    RuleContainsDetectionItemCondition(
                        field="EventID", value=mappedeventid
                    ),
                ],
            )
            for mappedproduct, servicedata in ocsf_windows_eventid_mapping.items()
            for mappedservice, eventiddata in servicedata.items()
            for mappedeventid, mappeddata in eventiddata.items()
            for field, value in sorted(mappeddata.items())
        ]
        # Field mappings for categories
        + [
            ProcessingItem(  # Sysmon hash lists are "ALG=value,...", OCSF hashes[].value holds bare values
                identifier="ocsf_value_hashes_strip_algorithm",
                transformation=ReplaceStringTransformation(
                    r"(?i)\b(?:MD5|SHA1|SHA256|SHA384|SHA512|IMPHASH)=", ""
                ),
                rule_conditions=[
                    LogsourceCondition(category=category)
                    for category in (
                        "create_stream_hash",
                        "driver_load",
                        "image_load",
                        "process_creation",
                    )
                ],
                rule_condition_linking=any,
                field_name_conditions=[IncludeFieldCondition(fields=["Hashes", "Hash"])],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for application)
                identifier="ocsf_field_mappings_application",
                transformation=FieldMappingTransformation(
                    {
                        "objectRef.namespace": "unmapped.objectRef.namespace",
                        "objectRef.subresource": "unmapped.objectRef.subresource",
                        "objectRef.resource": "unmapped.objectRef.resource",
                        "EventLog": "metadata.log_name",
                        "InterfaceUuid": "unmapped.InterfaceUuid",
                        "OpNum": "unmapped.OpNum",
                        "apiGroup": "unmapped.apiGroup",
                        "capabilities": "unmapped.capabilities",
                        "verb": "unmapped.verb",
                        "EventID": "metadata.event_code",
                        "logtype": "unmapped.logtype",
                        "hostPath": "unmapped.hostPath",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="application")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for antivirus)
                identifier="ocsf_field_mappings_antivirus",
                transformation=FieldMappingTransformation(
                    {
                        "Filename": "evidences.file.name",
                        "Signature": "finding_info.analytic.name",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="antivirus")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for create_remote_thread)
                identifier="ocsf_field_mappings_create_remote_thread",
                transformation=FieldMappingTransformation(
                    {
                        "SourceImage": "actor.process.file.path",
                        "SourceParentImage": "actor.process.parent_process.file.path",
                        "SourceCommandLine": "actor.process.cmd_line",
                        "TargetImage": "process.file.path",
                        "TargetParentProcessId": "process.parent_process.pid",
                        "StartModule": "module.file.path",
                        "StartFunction": "module.function_name",
                        "StartAddress": "module.start_address",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="create_remote_thread")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for create_stream_hash)
                identifier="ocsf_field_mappings_create_stream_hash",
                transformation=FieldMappingTransformation(
                    {
                        "Hash": "file.hashes.value",
                        "Image": "actor.process.file.path",
                        "Contents": "unmapped.Contents",
                        "TargetFilename": "file.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="create_stream_hash")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for dns)
                identifier="ocsf_field_mappings_dns",
                transformation=FieldMappingTransformation(
                    {
                        "answer": "answers.rdata",
                        "record_type": "query.type",
                        "query": "query.hostname",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="dns")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for dns_query)
                identifier="ocsf_field_mappings_dns_query",
                transformation=FieldMappingTransformation(
                    {
                        "QueryName": "query.hostname",
                        "Image": "actor.process.file.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="dns_query")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for driver_load)
                identifier="ocsf_field_mappings_driver_load",
                transformation=FieldMappingTransformation(
                    {
                        "Hashes": "driver.file.hashes.value",
                        "ImageLoaded": "driver.file.path",
                        "Signed": "unmapped.Signed",
                        "Signature": "driver.file.signature.certificate.subject",
                        "SignatureStatus": "driver.file.signature.state",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="driver_load")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for firewall)
                identifier="ocsf_field_mappings_firewall",
                transformation=FieldMappingTransformation(
                    {
                        "src_ip": "src_endpoint.ip",
                        "dst_ip": "dst_endpoint.ip",
                        "action": "unmapped.action",
                        "blocked": "unmapped.blocked",
                        "dst_port": "dst_endpoint.port",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="firewall")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for file_access)
                identifier="ocsf_field_mappings_file_access",
                transformation=FieldMappingTransformation(
                    {
                        "ParentImage": "actor.process.parent_process.file.path",
                        "Image": "actor.process.file.path",
                        "FileName": "file.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="file_access")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for file_change)
                identifier="ocsf_field_mappings_file_change",
                transformation=FieldMappingTransformation(
                    {
                        "CreationUtcTime": "file.created_time",
                        "Image": "actor.process.file.path",
                        "PreviousCreationUtcTime": "unmapped.PreviousCreationUtcTime",
                        "TargetFilename": "file.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="file_change")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for file_delete)
                identifier="ocsf_field_mappings_file_delete",
                transformation=FieldMappingTransformation(
                    {
                        "User": "actor.user.name",
                        "Image": "actor.process.file.path",
                        "TargetFilename": "file.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="file_delete")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for file_event)
                identifier="ocsf_field_mappings_file_event",
                transformation=FieldMappingTransformation(
                    {
                        "IntegrityLevel": "actor.process.integrity",
                        "CreationUtcTime": "file.created_time",
                        "User": "actor.user.name",
                        "ParentCommandLine": "actor.process.parent_process.cmd_line",
                        "ParentImage": "actor.process.parent_process.file.path",
                        "CommandLine": "actor.process.cmd_line",
                        "Image": "actor.process.file.path",
                        "TargetFilename": "file.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="file_event")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for file_executable_detected)
                identifier="ocsf_field_mappings_file_executable_detected",
                transformation=FieldMappingTransformation(
                    {
                        "TargetFilename": "file.path",
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(category="file_executable_detected")
                ],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for file_rename)
                identifier="ocsf_field_mappings_file_rename",
                transformation=FieldMappingTransformation(
                    {
                        "Image": "actor.process.file.path",
                        "SourceFilename": "file.path",
                        "TargetFilename": "file_result.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="file_rename")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for image_load)
                identifier="ocsf_field_mappings_image_load",
                transformation=FieldMappingTransformation(
                    {
                        "FileVersion": "module.file.version",
                        "Company": "module.file.company_name",
                        "Hashes": "module.file.hashes.value",
                        "SignatureStatus": "module.file.signature.state",
                        "Signed": "unmapped.Signed",
                        "CommandLine": "process.cmd_line",
                        "Description": "module.file.desc",
                        "OriginalFileName": "module.file.internal_name",
                        "Image": "process.file.path",
                        "Signature": "module.file.signature.certificate.subject",
                        "Product": "module.file.product.name",
                        "ImageLoaded": "module.file.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="image_load")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for network_connection)
                identifier="ocsf_field_mappings_network_connection",
                transformation=FieldMappingTransformation(
                    {
                        "Computer": "device.hostname",
                        "DestinationIsIpv6": "unmapped.DestinationIsIpv6",
                        "User": "actor.user.name",
                        "SourcePort": "src_endpoint.port",
                        "DestinationPort": "dst_endpoint.port",
                        "ParentImage": "actor.process.parent_process.file.path",
                        "CommandLine": "actor.process.cmd_line",
                        "SourceHostname": "src_endpoint.hostname",
                        "DestinationHostname": "dst_endpoint.hostname",
                        "SourceIsIpv6": "unmapped.SourceIsIpv6",
                        "Image": "actor.process.file.path",
                        "DestinationIp": "dst_endpoint.ip",
                        "SourceIp": "src_endpoint.ip",
                        "Initiated": "unmapped.Initiated",
                        "Protocol": "connection_info.protocol_name",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="network_connection")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for pipe_created)
                identifier="ocsf_field_mappings_pipe_created",
                transformation=FieldMappingTransformation(
                    {
                        "Image": "Image",
                        "PipeName": "PipeName",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="pipe_created")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for process_access)
                identifier="ocsf_field_mappings_process_access",
                transformation=FieldMappingTransformation(
                    {
                        "SourceCommandLine": "actor.process.cmd_line",
                        "SourceImage": "actor.process.file.path",
                        "GrantedAccess": "unmapped.GrantedAccess",
                        "Provider_Name": "metadata.log_provider",
                        "CallTrace": "unmapped.CallTrace",
                        "SourceUser": "actor.user.name",
                        "TargetImage": "process.file.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="process_access")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for process_creation)
                identifier="ocsf_field_mappings_process_creation",
                transformation=FieldMappingTransformation(
                    {
                        "GrandParentImage": "process.parent_process.parent_process.file.path",
                        "Hashes": "process.file.hashes.value",
                        "User": "process.user.name",
                        "CommandLine": "process.cmd_line",
                        "ParentCommandLine": "process.parent_process.cmd_line",
                        "Image": "process.file.path",
                        "Description": "process.file.desc",
                        "LogonId": "process.session.uid",
                        "CurrentDirectory": "process.working_directory",
                        "OriginalFileName": "process.file.internal_name",
                        "Provider_Name": "metadata.log_provider",
                        "ParentUser": "process.parent_process.user.name",
                        "FileVersion": "process.file.version",
                        "Company": "process.file.company_name",
                        "Product": "process.file.product.name",
                        "ParentImage": "process.parent_process.file.path",
                        "IntegrityLevel": "process.integrity",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="process_creation")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for process_tampering)
                identifier="ocsf_field_mappings_process_tampering",
                transformation=FieldMappingTransformation(
                    {
                        "Type": "unmapped.Type",
                        "Image": "process.file.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="process_tampering")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for process_termination)
                identifier="ocsf_field_mappings_process_termination",
                transformation=FieldMappingTransformation(
                    {
                        "Type": "unmapped.Type",
                        "Image": "process.file.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="process_termination")],
            )
        ]
        + [
            ProcessingItem(  # c-uri-extension holds a bare extension, match it as URL path suffix
                identifier="ocsf_value_proxy_c_uri_extension",
                transformation=ReplaceStringTransformation(
                    r"^\.?", "*.", interpret_special=True
                ),
                rule_conditions=[LogsourceCondition(category="proxy")],
                field_name_conditions=[IncludeFieldCondition(fields=["c-uri-extension"])],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for proxy)
                identifier="ocsf_field_mappings_proxy",
                transformation=FieldMappingTransformation(
                    {
                        "cs-uri-stem": "http_request.url.path",
                        "sc-status": "http_response.code",
                        "c-useragent": "http_request.user_agent",
                        "dst_ip": "dst_endpoint.ip",
                        "cs-uri": "http_request.url.url_string",
                        "cs-method": "http_request.http_method",
                        "c-uri-extension": "http_request.url.path",
                        "cs-host": "http_request.url.hostname",
                        "c-uri": "http_request.url.url_string",
                        "cs-cookie": "http_request.http_headers.value",
                        "c-uri-query": "http_request.url.query_string",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="proxy")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for ps_classic_provider_start)
                identifier="ocsf_field_mappings_ps_classic_provider_start",
                transformation=FieldMappingTransformation(
                    {
                        "Data": "Data",
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(category="ps_classic_provider_start")
                ],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for ps_classic_start)
                identifier="ocsf_field_mappings_ps_classic_start",
                transformation=FieldMappingTransformation(
                    {
                        "Data": "Data",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="ps_classic_start")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for ps_module)
                identifier="ocsf_field_mappings_ps_module",
                transformation=FieldMappingTransformation(
                    {
                        "ContextInfo": "unmapped.context_info",
                        "Payload": "script.script_content.value",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="ps_module")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for ps_script)
                identifier="ocsf_field_mappings_ps_script",
                transformation=FieldMappingTransformation(
                    {
                        "ScriptBlockText": "script.script_content.value",
                        "Path": "script.file.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="ps_script")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for raw_access_thread)
                identifier="ocsf_field_mappings_raw_access_thread",
                transformation=FieldMappingTransformation(
                    {
                        "Device": "Device",
                        "Image": "process.file.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="raw_access_thread")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for registry_add)
                identifier="ocsf_field_mappings_registry_add",
                transformation=FieldMappingTransformation(
                    {
                        "EventType": "unmapped.EventType",
                        "TargetObject": "reg_key.path",
                        "Image": "actor.process.file.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="registry_add")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for registry_delete)
                identifier="ocsf_field_mappings_registry_delete",
                transformation=FieldMappingTransformation(
                    {
                        "EventType": "unmapped.EventType",
                        "TargetObject": "reg_key.path",
                        "Image": "actor.process.file.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="registry_delete")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for registry_event)
                identifier="ocsf_field_mappings_registry_event",
                transformation=FieldMappingTransformation(
                    {
                        "NewName": "unmapped.NewName",
                        "TargetObject": "reg_key.path",
                        "Image": "actor.process.file.path",
                        "EventType": "unmapped.EventType",
                        "EventID": "metadata.event_code",
                        "Details": "unmapped.Details",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="registry_event")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for registry_rename)
                identifier="ocsf_field_mappings_registry_rename",
                transformation=FieldMappingTransformation(
                    {
                        "EventType": "unmapped.EventType",
                        "TargetObject": "reg_key.path",
                        "Image": "actor.process.file.path",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="registry_rename")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for registry_set)
                identifier="ocsf_field_mappings_registry_set",
                transformation=FieldMappingTransformation(
                    {
                        "User": "actor.user.name",
                        "TargetObject": "reg_value.path",
                        "Image": "actor.process.file.path",
                        "EventType": "unmapped.EventType",
                        "Details": "reg_value.data",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="registry_set")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for sysmon_error)
                identifier="ocsf_field_mappings_sysmon_error",
                transformation=FieldMappingTransformation(
                    {
                        "Description": "message",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="sysmon_error")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for sysmon_status)
                identifier="ocsf_field_mappings_sysmon_status",
                transformation=FieldMappingTransformation(
                    {
                        "State": "State",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="sysmon_status")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for webserver)
                identifier="ocsf_field_mappings_webserver",
                transformation=FieldMappingTransformation(
                    {
                        "cs-uri-query": "http_request.url.query_string",
                        "cs-method": "http_request.http_method",
                        "sc-status": "http_response.code",
                        "cs-user-agent": "http_request.user_agent",
                        "cs-referer": "http_request.referrer",
                        "cs-uri-stem": "http_request.url.path",
                        "cs-host": "http_request.url.hostname",
                        "cs-username": "actor.user.name",
                        "cs-content-type": "http_request.http_headers.value",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="webserver")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for wmi_event)
                identifier="ocsf_field_mappings_wmi_event",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "metadata.event_code",
                        "Destination": "Destination",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="wmi_event")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for windows security)
                identifier="ocsf_field_mappings_windows_security",
                transformation=FieldMappingTransformation(
                    {
                        "ParentProcessId": "unmapped.ParentProcessId",
                        "ClientProcessId": "unmapped.ClientProcessId",
                        "AccessList": "AccessList",
                        "AccessMask": "AccessMask",
                        "AllowedToDelegateTo": "AllowedToDelegateTo",
                        "Application": "Application",
                        "AttributeLDAPDisplayName": "AttributeLDAPDisplayName",
                        "AttributeValue": "AttributeValue",
                        "AuditPolicyChanges": "AuditPolicyChanges",
                        "AuditSourceName": "AuditSourceName",
                        "AuthenticationPackageName": "AuthenticationPackageName",
                        "CertThumbprint": "CertThumbprint",
                        "DestAddress": "dst_endpoint.ip",
                        "Destination": "Destination",
                        "DestPort": "dst_endpoint.port",
                        "EventID": "metadata.event_code",
                        "FilterName": "FilterName",
                        "FilterOrigin": "FilterOrigin",
                        "ImpersonationLevel": "ImpersonationLevel",
                        "IpAddress": "src_endpoint.ip",
                        "IpPort": "src_endpoint.port",
                        "KeyLength": "KeyLength",
                        "Keywords": "Keywords",
                        "LayerRTID": "LayerRTID",
                        "LogonProcessName": "LogonProcessName",
                        "LogonType": "logon_type_id",
                        "NewTargetUserName": "NewTargetUserName",
                        "NewTemplateContent": "NewTemplateContent",
                        "NewUacValue": "NewUacValue",
                        "NewValue": "NewValue",
                        "ObjectClass": "ObjectClass",
                        "ObjectName": "ObjectName",
                        "ObjectServer": "ObjectServer",
                        "ObjectType": "ObjectType",
                        "ObjectValueName": "ObjectValueName",
                        "OldUacValue": "OldUacValue",
                        "param1": "param1",
                        "PrivilegeList": "PrivilegeList",
                        "ProcessName": "ProcessName",
                        "Properties": "Properties",
                        "Provider_Name": "metadata.log_provider",
                        "ProviderContextName": "ProviderContextName",
                        "RelativeTargetName": "RelativeTargetName",
                        "SamAccountName": "SamAccountName",
                        "Service": "Service",
                        "ServiceFileName": "win_service.cmd_line",
                        "ServiceName": "win_service.name",
                        "ServicePrincipalNames": "ServicePrincipalNames",
                        "ServiceStartType": "unmapped.ServiceStartType",
                        "ServiceType": "unmapped.ServiceType",
                        "ShareName": "ShareName",
                        "SidHistory": "SidHistory",
                        "SourceAddress": "src_endpoint.ip",
                        "SourcePort": "src_endpoint.port",
                        "Status": "Status",
                        "SubcategoryGuid": "SubcategoryGuid",
                        "SubjectDomainName": "SubjectDomainName",
                        "SubjectLogonId": "SubjectLogonId",
                        "SubjectUserName": "SubjectUserName",
                        "SubjectUserSid": "SubjectUserSid",
                        "TargetName": "TargetName",
                        "TargetOutboundUserName": "TargetOutboundUserName",
                        "TargetServerName": "TargetServerName",
                        "TargetUserName": "user.name",
                        "TargetUserSid": "TargetUserSid",
                        "TaskContent": "TaskContent",
                        "TaskContentNew": "TaskContentNew",
                        "TaskName": "TaskName",
                        "TemplateContent": "TemplateContent",
                        "TicketEncryptionType": "TicketEncryptionType",
                        "TicketOptions": "TicketOptions",
                        "Workstation": "Workstation",
                        "WorkstationName": "src_endpoint.name",
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(product="windows"),
                    LogsourceCondition(service="security"),
                ],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for windows system, eventid 7045)
                identifier="ocsf_field_mappings_windows_system_7045",
                transformation=FieldMappingTransformation(
                    {
                        "EventID": "metadata.event_code",
                        "ImagePath": "win_service.cmd_line",
                        "ServiceName": "win_service.name",
                        "AccountName": "unmapped.service_account_name",
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(product="windows"),
                    LogsourceCondition(service="system"),
                    RuleContainsFieldCondition(field="EventID"),
                    RuleContainsDetectionItemCondition(field="EventID", value=7045),
                ],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for windows system)
                identifier="ocsf_field_mappings_windows_system",
                transformation=FieldMappingTransformation(
                    {
                        "AccountName": "unmapped.AccountName",
                        "Caption": "unmapped.Caption",
                        "Channel": "unmapped.Channel",
                        "Description": "unmapped.Description",
                        "DeviceName": "unmapped.DeviceName",
                        "EventID": "metadata.event_code",
                        "HiveName": "unmapped.HiveName",
                        "ImagePath": "unmapped.ImagePath",
                        "Level": "unmapped.Level",
                        "Origin": "unmapped.Origin",
                        "param1": "unmapped.param1",
                        "param2": "unmapped.param2",
                        "param3": "unmapped.param3",
                        "ProcessId": "unmapped.ProcessId",
                        "Provider_Name": "metadata.log_provider",
                        "ServiceName": "unmapped.ServiceName",
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(product="windows"),
                    LogsourceCondition(service="system"),
                ],
            )
        ]
        # Convert EventID aka metadata.event_code to str
        + [
            ProcessingItem(
                identifier="ocsf_change_field_mapping_to_str",
                transformation=ConvertTypeTransformation("str"),
                field_name_conditions=[
                    IncludeFieldCondition(fields=["metadata.event_code"])
                ],
            )
        ],
    )
