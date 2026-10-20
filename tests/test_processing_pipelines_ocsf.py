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
        'type_uid=100704 and actor.process.file.path="test.exe" '
        'and actor.process.parent_process.file.path="TestSourceParentImage" '
        'and module.function_name="TestStartFunction" and module.start_address="TestStartAddress" '
        'and actor.process.cmd_line="TestSourceCommandLine" and module.file.path="TestStartModule" '
        'and process.file.path="TestTargetImage"'
    ]


def test_ocsf_create_stream_hash(backend, create_stream_hash_sigma_rule):
    assert backend.convert(create_stream_hash_sigma_rule) == [
        'type_uid=100103 and unmapped.Contents="TestContent" and file.hashes.value="68b329da9893e34099c7d8ad5cb9c940" and actor.process.file.path="test.exe" and file.path="test.txt"'
    ]


def test_ocsf_dns(backend, dns_sigma_rule):
    assert backend.convert(dns_sigma_rule) == [
        'class_uid=4003 and answers.rdata="1.1.1.1" and query.type="A" and query.hostname="gist.github.com"'
    ]


def test_ocsf_dns_query(backend, dns_query_sigma_rule):
    assert backend.convert(dns_query_sigma_rule) == [
        'class_uid=4003 and query.hostname="gist.github.com" and actor.process.file.path="test.exe"'
    ]


def test_ocsf_driver_load(backend, driver_load_sigma_rule):
    assert backend.convert(driver_load_sigma_rule) == [
        'type_uid=100201 and driver.file.path="test.exe" and (driver.file.hashes.value in ("68b329da9893e34099c7d8ad5cb9c940", "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc"))'
    ]


def test_ocsf_firewall(backend, firewall_sigma_rule):
    assert backend.convert(firewall_sigma_rule) == [
        'class_uid=4001 and unmapped.action="allow" and unmapped.blocked=0 and dst_endpoint.port=80'
    ]


def test_ocsf_file_access(backend, file_access_sigma_rule):
    assert backend.convert(file_access_sigma_rule) == [
        'type_uid=100114 and actor.process.file.path="Test" and file.path="test.exe"'
    ]


def test_ocsf_file_change(backend, file_change_sigma_rule):
    assert backend.convert(file_change_sigma_rule) == [
        'type_uid=100103 and file.path="test"'
    ]


def test_ocsf_file_delete(backend, file_delete_sigma_rule):
    assert backend.convert(file_delete_sigma_rule) == [
        'type_uid=100104 and actor.user.name="test" and actor.process.file.path="test" and file.path="test"'
    ]


def test_ocsf_file_event(backend, file_event_sigma_rule):
    assert backend.convert(file_event_sigma_rule) == [
        'type_uid=100101 and file.path="test.exe" and actor.process.file.path endswith "\\powershell.exe" '
        'and actor.process.parent_process.file.path endswith "\\explorer.exe" '
        'and actor.process.cmd_line="test.exe /foo /bar"'
    ]


def test_ocsf_file_executable_detected(backend, file_executable_detected_sigma_rule):
    assert backend.convert(file_executable_detected_sigma_rule) == [
        'type_uid=100101 and file.path="test.exe"'
    ]


def test_ocsf_file_rename(backend, file_rename_detected_sigma_rule):
    assert backend.convert(file_rename_detected_sigma_rule) == [
        'type_uid=100105 and file.path="test.exe" and file_result.path="test-new.exe"'
    ]


# ToDo Check here
def test_ocsf_image_load(backend, image_load_sigma_rule):
    assert backend.convert(image_load_sigma_rule) == [
        'class_uid=1007 and not module.file.path is null and process.file.path="test.exe" and module.file.path="test.dll" '
        'and unmapped.Signed="false" and module.file.hashes.value contains "AABB" '
        'and module.file.internal_name="test.dll"'
    ]


def test_ocsf_network_connect(backend, network_connection_sigma_rule):
    assert backend.convert(network_connection_sigma_rule) == [
        'class_uid=4001 and unmapped.Initiated="true" and dst_endpoint.ip="1.2.3.4" '
        'and connection_info.protocol_name="tcp" and actor.process.file.path="test.exe" '
        'and actor.process.parent_process.file.path="parent.exe" '
        'and actor.process.cmd_line="test.exe foo bar" and unmapped.SourceIsIpv6="false"'
    ]


def test_ocsf_process_access(backend, process_access_sigma_rule):
    assert backend.convert(process_access_sigma_rule) == [
        'type_uid=100703 and actor.process.file.path="source.exe" '
        'and process.file.path="test.exe" and unmapped.GrantedAccess="0x1010"'
    ]


def test_ocsf_process_creation(backend, process_creation_sigma_rule):
    assert backend.convert(process_creation_sigma_rule) == [
        'type_uid=100701 and process.cmd_line="test.exe foo bar" and process.file.path endswith "\\test.exe" '
        'and process.file.hashes.value contains "8C8B6E5D" and process.integrity="High"'
    ]


def test_ocsf_process_tampering(backend, process_tampering_sigma_rule):
    assert backend.convert(process_tampering_sigma_rule) == [
        'type_uid=100799 and process.file.path="test.exe"'
    ]


def test_ocsf_process_termination(backend, process_termination_sigma_rule):
    assert backend.convert(process_termination_sigma_rule) == [
        'type_uid=100702 and process.file.path="test.exe"'
    ]


def test_ocsf_raw_access_thread(backend, raw_access_thread_sigma_rule):
    assert backend.convert(raw_access_thread_sigma_rule) == ['process.file.path="test.exe"']


def test_ocsf_registry_add(backend, registry_add_sigma_rule):
    assert backend.convert(registry_add_sigma_rule) == [
        'type_uid=20100101 and reg_key.path="test.exe"'
    ]


def test_ocsf_registry_delete(backend, registry_delete_sigma_rule):
    assert backend.convert(registry_delete_sigma_rule) == [
        'type_uid=20100104 and reg_key.path="test.exe"'
    ]


def test_ocsf_registry_event(backend, registry_event_sigma_rule):
    assert backend.convert(registry_event_sigma_rule) == [
        'class_uid=201001 and reg_key.path="HKLM\\Software\\Test" and actor.process.file.path="test.exe"'
    ]


def test_ocsf_registry_rename(backend, registry_rename_sigma_rule):
    assert backend.convert(registry_rename_sigma_rule) == [
        'type_uid=20100105 and reg_key.path="test.exe"'
    ]


def test_ocsf_registry_set(backend, registry_set_sigma_rule):
    assert backend.convert(registry_set_sigma_rule) == [
        'type_uid=20100202 and reg_value.path="test.exe" and reg_value.data="DWORD (0x00000001)"'
    ]


def test_ocsf_sysmon_error(backend, sysmon_error_sigma_rule):
    assert backend.convert(sysmon_error_sigma_rule) == [
        'type_uid=600801 and message="a error is here"'
    ]


def test_ocsf_ps_script(backend, ps_script_sigma_rule):
    assert backend.convert(ps_script_sigma_rule) == [
        'type_uid=100901 and script.script_content.value="Test" and script.file.path="Test"'
    ]


def test_ocsf_ps_module(backend, ps_module_sigma_rule):
    assert backend.convert(ps_module_sigma_rule) == [
        'type_uid=100901 and unmapped.context_info="Test" and script.script_content.value="Test"'
    ]


def test_ocsf_proxy(backend, proxy_sigma_rule):
    assert backend.convert(proxy_sigma_rule) == [
        'class_uid=4002 and http_request.user_agent="Test-UA" and dst_endpoint.ip="1.1.1.1" '
        'and http_request.url.url_string="/test/test.exe" and http_request.http_method="GET" '
        'and http_request.url.path endswith ".exe" and http_request.url.hostname="github.com" '
        'and http_request.url.url_string="/test/test.exe" and http_request.http_headers.value="Test-Cookie" '
        'and http_request.url.query_string match "?test=test" and http_response.code=200'
    ]


def test_ocsf_webserver(backend, webserver_sigma_rule):
    assert backend.convert(webserver_sigma_rule) == [
        'class_uid=4002 and http_request.url.query_string="/test/test.exe" and http_request.http_method="GET" '
        'and http_response.code="Test" and http_request.user_agent="Test-UA" '
        'and http_request.referrer="Test-Referer" and http_request.url.path="/test/upload.aspx" '
        'and http_request.url.hostname="example.com" and actor.user.name="anonymous" '
        'and http_request.http_headers.value="application/octet-stream"'
    ]
