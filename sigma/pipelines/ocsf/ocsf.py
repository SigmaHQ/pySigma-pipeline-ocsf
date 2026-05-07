from sigma.pipelines.base import Pipeline
from sigma.processing.transformations import (
    AddConditionTransformation,
    FieldMappingTransformation,
    ConvertTypeTransformation,
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
    # "create_remote_thread": 8,
    "create_stream_hash": {"type_uid": 100103},
    "dns": {"class_uid": 4003},
    "dns_query": {"class_uid": 4003},
    "driver_load": {"type_uid": 100702},
    "firewall": {"class_uid": 4001},
    "file_access": {"type_uid": 100114},
    "file_change": {"type_uid": 100103},
    "file_delete": {"type_uid": 100104},
    "file_event": {"type_uid": 100101},
    "file_executable_detected": {"type_uid": 100101},
    "file_rename": {"type_uid": 100105},
    "image_load": {
        "type_uid": 100799,
        "activity_name": "Load",
    },
    "network_connection": {"class_uid": 4001},
    # "pipe_created": [17, 18],
    "process_access": {
        "type_uid": 100799,
        "activity_name": "Access",
    },
    "process_creation": {"type_uid": 100701},
    "process_tampering": {
        "type_uid": 100704,
    },
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
}


@Pipeline  # type: ignore
def ocsf_pipeline() -> ProcessingPipeline:
    return ProcessingPipeline(
        name="OCSF pipeline",
        allowed_backends=frozenset(),  # Set of identifiers of backends (from the backends mapping) that are allowed to use this processing pipeline. This can be used by frontends like Sigma CLI to warn the user about inappropriate usage.
        priority=20,  # The priority defines the order pipelines are applied. See documentation for common values.
        items=[
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
                        "SourceParentImage": "file_result.name",
                        "SourceImage": "file.name",
                        "TargetParentProcessId": "unmapped.TargetParentProcessId",
                        "StartFunction": "unmapped.StartFunction",
                        "StartAddress": "unmapped.StartAddress",
                        "SourceCommandLine": "unmapped.SourceCommandLine",
                        "StartModule": "unmapped.StartModule",
                        "TargetImage": "file_result.name",
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
                        "Image": "file.name",
                        "Contents": "unmapped.Contents",
                        "TargetFilename": "file.name",
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
                        "answer": "answer.rdata",
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
                        "Image": "query.hostname",
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
                        "Hashes": "process.file.hashes.value",
                        "ImageLoaded": "process.file.name",
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
                        "Image": "file.name",
                        "FileName": "file.name",
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
                        "Image": "file.name",
                        "PreviousCreationUtcTime": "unmapped.PreviousCreationUtcTime",
                        "TargetFilename": "file.name",
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
                        "Image": "file.name",
                        "TargetFilename": "file.name",
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
                        "ParentCommandLine": "process.parent_process.cmd_line",
                        "ParentImage": "file.name",
                        "CommandLine": "process.cmd_line",
                        "Image": "file.name",
                        "TargetFilename": "file.name",
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
                        "TargetFilename": "file.name",
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
                        "SourceFilename": "file.name",
                        "TargetFilename": "file_result.file.name",
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
                        "Company": "Company",
                        "Hashes": "process.file.hashes.value",
                        "SignatureStatus": "SignatureStatus",
                        "Signed": "Signed",
                        "CommandLine": "process.cmd_line",
                        "Description": "Description",
                        "OriginalFileName": "process.file.internal_name",
                        "Image": "process.file.name",
                        "Signature": "Signature",
                        "Product": "Product",
                        "ImageLoaded": "process.file.name",
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
                        "SourcePort": "src_endpoint.port",
                        "DestinationPort": "dst_endpoint.port",
                        "ParentImage": "ParentImage",
                        "CommandLine": "CommandLine",
                        "SourceHostname": "src_endpoint.hostname",
                        "DestinationHostname": "dst_endpoint.hostname",
                        "SourceIsIpv6": "SourceIsIpv6",
                        "Image": "Image",
                        "DestinationIp": "dst_endpoint.ip",
                        "SourceIp": "src_endpoint.ip",
                        "Initiated": "Initiated",
                        "Protocol": "protocol_name",
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
                        "SourceImage": "parent_process.name",
                        "GrantedAccess": "GrantedAccess",
                        "Provider_Name": "Provider_Name",
                        "CallTrace": "CallTrace",
                        "SourceUser": "SourceUser",
                        "TargetImage": "process.name",
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
                        "Hashes": "Hashes",
                        "User": "process.user.name",
                        "CommandLine": "process.cmd_line",
                        "ParentCommandLine": "process.parent_process.cmd_line",
                        "Image": "process.name",
                        "Description": "process.file.desc",
                        "LogonId": "process.session.uid",
                        "CurrentDirectory": "process.working_directory",
                        "OriginalFileName": "process.file.internal_name",
                        "Provider_Name": "Provider_Name",
                        "ParentUser": "ParentUser",
                        "FileVersion": "FileVersion",
                        "Company": "Company",
                        "Product": "Product",
                        "ParentImage": "process.parent_process.name",
                        "IntegrityLevel": "IntegrityLevel",
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
                        "Type": "Type",
                        "Image": "process.name",
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
                        "Type": "Type",
                        "Image": "process.name",
                    }
                ),
                rule_conditions=[LogsourceCondition(category="process_termination")],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for proxy)
                identifier="ocsf_field_mappings_proxy",
                transformation=FieldMappingTransformation(
                    {
                        "c-useragent": "c-useragent",
                        "dst_ip": "dst_ip",
                        "cs-uri": "cs-uri",
                        "cs-method": "cs-method",
                        "c-uri-extension": "c-uri-extension",
                        "cs-host": "cs-host",
                        "c-uri": "c-uri",
                        "cs-cookie": "cs-cookie",
                        "c-uri-query": "c-uri-query",
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
                        "ContextInfo": "ContextInfo",
                        "Payload": "Payload",
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
                        "ScriptBlockText": "ScriptBlockText",
                        "Path": "Path",
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
                        "Image": "Image",
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
                        "EventType": "EventType",
                        "TargetObject": "reg_key.path",
                        "Image": "reg_key.path",
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
                        "EventType": "EventType",
                        "TargetObject": "reg_key.path",
                        "Image": "reg_key.path",
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
                        "NewName": "NewName",
                        "TargetObject": "reg_key.path",
                        "Image": "reg_key.path",
                        "EventType": "EventType",
                        "EventID": "metadata.event_code",
                        "Details": "Details",
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
                        "EventType": "EventType",
                        "TargetObject": "reg_key.path",
                        "Image": "reg_key.path",
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
                        "User": "User",
                        "TargetObject": "reg_key.path",
                        "Image": "reg_key.path",
                        "EventType": "EventType",
                        "Details": "Details",
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
                        "cs-uri-query": "cs-uri-query",
                        "cs-method": "cs-method",
                        "sc-status": "sc-status",
                        "cs-user-agent": "cs-user-agent",
                        "cs-referer": "cs-referer",
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
                        "DestAddress": "DestAddress",
                        "Destination": "Destination",
                        "DestPort": "DestPort",
                        "EventID": "metadata.event_code",
                        "FilterName": "FilterName",
                        "FilterOrigin": "FilterOrigin",
                        "ImpersonationLevel": "ImpersonationLevel",
                        "IpAddress": "src_endpoint.ip",
                        "IpPort": "IpPort",
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
                        "Provider_Name": "unmapped.SourceName",
                        "ProviderContextName": "ProviderContextName",
                        "RelativeTargetName": "RelativeTargetName",
                        "SamAccountName": "SamAccountName",
                        "Service": "Service",
                        "ServiceFileName": "win_service.cmd_line",
                        "ServiceName": "win_service.name",
                        "ServicePrincipalNames": "ServicePrincipalNames",
                        "ServiceStartType": "ServiceStartType",
                        "ServiceType": "ServiceType",
                        "ShareName": "ShareName",
                        "SidHistory": "SidHistory",
                        "SourceAddress": "SourceAddress",
                        "SourcePort": "SourcePort",
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
                identifier="ocsf_field_mappings_windows_system",
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
        + [
            ProcessingItem(  # Field mappings for windows system)
                identifier="ocsf_field_mappings_windows_system",
                transformation=FieldMappingTransformation(
                    {
                        "ScriptBlockText": "script.script_content",
                        "Path": "script.file.path",
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(category="ps_script"),
                ],
            )
        ]
        + [
            ProcessingItem(  # Field mappings for windows system)
                identifier="ocsf_field_mappings_windows_system",
                transformation=FieldMappingTransformation(
                    {
                        "Payload": "script.script_content",
                        "ContextInfo": "unmapped.context_info",
                    }
                ),
                rule_conditions=[
                    LogsourceCondition(category="ps_module"),
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
