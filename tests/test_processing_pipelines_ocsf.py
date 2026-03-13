def test_ocsf_application(backend, application_sigma_rule):
    assert backend.convert(application_sigma_rule) == [
        'class_uid=6002 and category_uid=6 and unmapped.objectRef.namespace="Test" and unmapped.objectRef.subresource="Test" and unmapped.objectRef.resource="Test" and metadata.log_name="Test" and unmapped.InterfaceUuid="Test" and unmapped.OpNum="Test" and unmapped.apiGroup="Test" and unmapped.capabilities="Test" and unmapped.verb="Test" and metadata.event_code="Test" and unmapped.logtype="Test" and unmapped.hostPath="Test"'
    ]


def test_ocsf_antivirus(backend, antivirus_sigma_rule):
    assert backend.convert(antivirus_sigma_rule) == [
        'class_uid=2004 and category_uid=2 and evidences.file.name="test.exe" and finding_info.analytic.name="Test Signature"'
    ]


def test_ocsf_create_remote_thread(backend, create_remote_thread_sigma_rule):
    assert backend.convert(create_remote_thread_sigma_rule) == [
        'file.name="test.exe" and file_result.name="TestSourceParentImage" and unmapped.StartFunction="TestStartFunction" and unmapped.StartAddress="TestStartAddress" and unmapped.SourceCommandLine="TestSourceCommandLine" and unmapped.StartModule="TestStartModule" and file_result.name="TestTargetImage"'
    ]


def test_ocsf_create_stream_hash(backend, create_stream_hash_sigma_rule):
    assert backend.convert(create_stream_hash_sigma_rule) == [
        'class_uid=1001 and category_uid=1 and activity_id=3 and unmapped.Contents="TestContent" and file.hashes.value="68b329da9893e34099c7d8ad5cb9c940" and file.name="test.exe" and file.name="test.txt"'
    ]


def test_ocsf_dns(backend, dns_sigma_rule):
    assert backend.convert(dns_sigma_rule) == [
        'class_uid=4003 and category_uid=4 and answer.rdata="1.1.1.1" and query.type="A" and query.hostname="gist.github.com"'
    ]


def test_ocsf_dns_query(backend, dns_query_sigma_rule):
    assert backend.convert(dns_query_sigma_rule) == [
        'class_uid=4003 and category_uid=4 and query.hostname="gist.github.com"'
    ]


def test_ocsf_driver_load(backend, driver_load_sigma_rule):
    assert backend.convert(driver_load_sigma_rule) == [
        'class_uid=1007 and category_uid=1 and activity_id=2 and process.file.name="test.exe" and (process.file.hashes.value in ("68b329da9893e34099c7d8ad5cb9c940", "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc"))'
    ]


def test_ocsf_firewall(backend, firewall_sigma_rule):
    assert backend.convert(firewall_sigma_rule) == [
        'class_uid=4001 and category_uid=4 and unmapped.action="allow" and unmapped.blocked=0 and dst_endpoint.port=80'
    ]


def test_ocsf_file_access(backend, file_access_sigma_rule):
    assert backend.convert(file_access_sigma_rule) == [
        'class_uid=1001 and category_uid=1 and activity_id=14 and file.name contains-all ("Test", "test.exe")'
    ]


def test_ocsf_file_change(backend, file_change_sigma_rule):
    assert backend.convert(file_change_sigma_rule) == [
        'class_uid=1001 and category_uid=1 and activity_id=3 and file.name="test"'
    ]


def test_ocsf_file_delete(backend, file_delete_sigma_rule):
    assert backend.convert(file_delete_sigma_rule) == [
        'class_uid=1001 and category_uid=1 and activity_id=4 and actor.user.name="test" and file.name="test" and file.name="test"'
    ]


def test_ocsf_file_event(backend, file_event_sigma_rule):
    assert backend.convert(file_event_sigma_rule) == [
        'class_uid=1001 and category_uid=1 and activity_id=1 and file.name="test.exe" and process.cmd_line="test.exe /foo /bar"'
    ]


def test_ocsf_file_executable_detected(backend, file_executable_detected_sigma_rule):
    assert backend.convert(file_executable_detected_sigma_rule) == [
        'class_uid=1001 and category_uid=1 and activity_id=1 and file.name="test.exe"'
    ]


def test_ocsf_file_rename(backend, file_rename_detected_sigma_rule):
    assert backend.convert(file_rename_detected_sigma_rule) == [
        'class_uid=1001 and category_uid=1 and activity_id=5 and file.name="test.exe" and file_result.file.name="test-new.exe"'
    ]


# ToDo Check here
def test_ocsf_image_load(backend, image_load_sigma_rule):
    assert backend.convert(image_load_sigma_rule) == [
        'class_uid=1007 and category_uid=1 and activity_name="Load" and activity_id=99 and process.file.name="test.exe"'
    ]


def test_ocsf_network_connect(backend, network_connection_sigma_rule):
    assert backend.convert(network_connection_sigma_rule) == [
        'class_uid=4001 and category_uid=4 and Initiated="true" and dst_endpoint.ip="1.2.3.4"'
    ]


def test_ocsf_process_access(backend, process_access_sigma_rule):
    assert backend.convert(process_access_sigma_rule) == [
        'class_uid=1007 and category_uid=1 and activity_name="Access" and activity_id=99 and process.name="test.exe"'
    ]


def test_ocsf_process_creation(backend, process_creation_sigma_rule):
    assert backend.convert(process_creation_sigma_rule) == [
        'class_uid=1007 and category_uid=1 and activity_id=1 and process.cmd_line="test.exe foo bar" and process.name endswith "\\test.exe"'
    ]


def test_ocsf_process_tampering(backend, process_tampering_sigma_rule):
    assert backend.convert(process_tampering_sigma_rule) == [
        'class_uid=1007 and category_uid=1 and activity_id=4 and process.name="test.exe"'
    ]


def test_ocsf_process_termination(backend, process_termination_sigma_rule):
    assert backend.convert(process_termination_sigma_rule) == [
        'class_uid=1007 and category_uid=1 and activity_id=2 and process.name="test.exe"'
    ]


def test_ocsf_raw_access_thread(backend, raw_access_thread_sigma_rule):
    assert backend.convert(raw_access_thread_sigma_rule) == ['Image="test.exe"']


def test_ocsf_registry_add(backend, registry_add_sigma_rule):
    assert backend.convert(registry_add_sigma_rule) == [
        'class_uid=201001 and category_uid=1 and activity_id=1 and reg_key.path="test.exe"'
    ]


def test_ocsf_registry_delete(backend, registry_delete_sigma_rule):
    assert backend.convert(registry_delete_sigma_rule) == [
        'class_uid=201001 and category_uid=1 and activity_id=4 and reg_key.path="test.exe"'
    ]


def test_ocsf_registry_event(backend, registry_event_sigma_rule):
    assert backend.convert(registry_event_sigma_rule) == [
        'class_uid=201001 and category_uid=1 and reg_key.path="test.exe"'
    ]


def test_ocsf_registry_rename(backend, registry_rename_sigma_rule):
    assert backend.convert(registry_rename_sigma_rule) == [
        'class_uid=201001 and category_uid=1 and activity_id=5 and reg_key.path="test.exe"'
    ]


def test_ocsf_registry_set(backend, registry_set_sigma_rule):
    assert backend.convert(registry_set_sigma_rule) == [
        'class_uid=201001 and category_uid=1 and activity_id=3 and reg_key.path="test.exe"'
    ]


def test_ocsf_sysmon_error(backend, sysmon_error_sigma_rule):
    assert backend.convert(sysmon_error_sigma_rule) == [
        'class_uid=6008 and category_uid=6 and activity_id=1 and message="a error is here"'
    ]


def test_ocsf_ps_script(backend, ps_script_sigma_rule):
    assert backend.convert(ps_script_sigma_rule) == [
        'type_uid=100901 and script.script_content="Test" and script.file.path="Test"'
    ]


def test_ocsf_ps_module(backend, ps_module_sigma_rule):
    assert backend.convert(ps_module_sigma_rule) == [
        'type_uid=100901 and unmapped.ContextInfo="Test" and unmapped.Payload="Test"'
    ]
