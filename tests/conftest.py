import pytest
from sigma.backends.test import TextQueryTestBackend
from sigma.pipelines.ocsf import ocsf_pipeline
from sigma.collection import SigmaCollection


@pytest.fixture
def backend():
    backend = TextQueryTestBackend(ocsf_pipeline())
    backend.field_quote = ""
    return backend


@pytest.fixture
def application_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Application Test
        status: test
        logsource:
            category: application
        detection:
            sel:
                objectRef.namespace: Test
                objectRef.subresource: Test
                objectRef.resource: Test
                EventLog: Test
                InterfaceUuid: Test
                OpNum: Test
                apiGroup: Test
                capabilities: Test
                verb: Test
                EventID: Test
                logtype: Test
                hostPath: Test
            condition: sel
    """)


@pytest.fixture
def antivirus_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Antivirus Test
        status: test
        logsource:
            category: antivirus
        detection:
            sel:
                Filename: test.exe
                Signature: Test Signature
            condition: sel
    """)


@pytest.fixture
def create_remote_thread_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Create Remote Thread Test
        status: test
        logsource:
            category: create_remote_thread
            product: windows
        detection:
            sel:
                SourceImage: test.exe
                SourceParentImage: TestSourceParentImage
                StartFunction: TestStartFunction
                StartAddress: TestStartAddress
                SourceCommandLine: TestSourceCommandLine
                StartModule: TestStartModule
                TargetImage: TestTargetImage
            condition: sel
    """)


@pytest.fixture
def create_stream_hash_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Create Stream Hash Test
        status: test
        logsource:
            category: create_stream_hash
            product: windows
        detection:
            sel:
                Contents: TestContent
                Hash: 68b329da9893e34099c7d8ad5cb9c940
                Image: test.exe
                TargetFilename: test.txt
            condition: sel
    """)


@pytest.fixture
def dns_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Dns Test
        status: test
        logsource:
            category: dns
        detection:
            sel:
                answer: 1.1.1.1
                record_type: A
                query: gist.github.com
            condition: sel
    """)


@pytest.fixture
def dns_query_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Dns Query Test
        status: test
        logsource:
            category: dns_query
            product: windows
        detection:
            sel:
                QueryName: gist.github.com
            condition: sel
    """)


@pytest.fixture
def driver_load_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Driver Load Test
        status: test
        logsource:
            category: driver_load
            product: windows
        detection:
            sel:
                ImageLoaded: test.exe
                Hashes:
                  - 68b329da9893e34099c7d8ad5cb9c940
                  - adc83b19e793491b1c6ea0fd8b46cd9f32e592fc
            condition: sel
    """)


@pytest.fixture
def firewall_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Firewall Test
        status: test
        logsource:
            category: firewall
        detection:
            sel:
                action: allow
                blocked: false
                dst_port: 80
            condition: sel
    """)


@pytest.fixture
def file_access_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: File Access Test
        status: test
        logsource:
            category: file_access
            product: windows
        detection:
            sel:
                Image: Test
                FileName: test.exe
            condition: sel
    """)


@pytest.fixture
def file_change_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: File Change Test
        status: test
        logsource:
            category: file_change
            product: windows
        detection:
            sel:
                TargetFilename: test
            condition: sel
    """)


@pytest.fixture
def file_delete_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: File Delete Test
        status: test
        logsource:
            category: file_delete
            product: windows
        detection:
            sel:
                User: test
                Image: test
                TargetFilename: test
            condition: sel
    """)


@pytest.fixture
def file_event_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: File Event Test
        status: test
        logsource:
            category: file_event
            product: windows
        detection:
            sel:
                TargetFilename: test.exe
                CommandLine: test.exe /foo /bar
            condition: sel
    """)


@pytest.fixture
def file_executable_detected_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: File Executable Detected Test
        status: test
        logsource:
            category: file_executable_detected
            product: windows
        detection:
            sel:
                TargetFilename: test.exe
            condition: sel
    """)


@pytest.fixture
def file_rename_detected_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: File Executable Detected Test
        status: test
        logsource:
            category: file_rename
            product: windows
        detection:
            sel:
                SourceFilename: test.exe
                TargetFilename: test-new.exe
            condition: sel
    """)


@pytest.fixture
def image_load_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Image Load Test
        status: test
        logsource:
            category: image_load
            product: windows
        detection:
            sel:
                ImageLoaded: test.exe
            condition: sel
    """)


@pytest.fixture
def network_connection_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Network Connection Test
        status: test
        logsource:
            category: network_connection
            product: windows
        detection:
            sel:
               Initiated: "true"
               DestinationIp: "1.2.3.4"
            condition: sel
    """)


@pytest.fixture
def pipe_created_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Pipe Created Test
        status: test
        logsource:
            category: pipe_created
            product: windows
        detection:
            sel:
               Image: Test
               PipeName": TestPipe
            condition: sel
    """)


@pytest.fixture
def process_access_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Process Access Test
        status: test
        logsource:
            category: process_access
            product: windows
        detection:
            sel:
                TargetImage: test.exe
            condition: sel
    """)


@pytest.fixture
def process_creation_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Process Creation Test
        status: test
        logsource:
            category: process_creation
            product: windows
        detection:
            sel:
                CommandLine: "test.exe foo bar"
                Image: "*\\\\test.exe"
            condition: sel
    """)


@pytest.fixture
def process_tampering_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Process Tampering Test
        status: test
        logsource:
            category: process_tampering
            product: windows
        detection:
            sel:
                Image: test.exe
            condition: sel
    """)


@pytest.fixture
def process_termination_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Process Termination Test
        status: test
        logsource:
            category: process_termination
            product: windows
        detection:
            sel:
                Image: test.exe
            condition: sel
    """)


@pytest.fixture
def proxy_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Process Termination Test
        status: test
        logsource:
            category: proxy
        detection:
            sel:
                c-useragent: Test-UA
                dst_ip: 1.1.1.1
                cs-uri: /test/test.exe
                cs-method: GET
                c-uri-extension: test-extension
                cs-host: github.com
                c-uri: /test/test.exe
                cs-cookie: Test-Cookie
                c-uri-query: ?test=test
            condition: sel
    """)


@pytest.fixture
def ps_classic_provider_start_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: PS Classic Provider Test
        status: test
        logsource:
            category: ps_classic_provider_start
        detection:
            sel:
                Data: test-data
            condition: sel
    """)


@pytest.fixture
def ps_classic_start_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: PS Classic Start Test
        status: test
        logsource:
            category: ps_classic_start
        detection:
            sel:
                Data: test-data
            condition: sel
    """)


@pytest.fixture
def ps_module_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: PS Module Test
        status: test
        logsource:
            category: ps_module
        detection:
            sel:
                ContextInfo: Test
                Payload: Test
            condition: sel
    """)


@pytest.fixture
def ps_script_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: PS Script Test
        status: test
        logsource:
            category: ps_script
        detection:
            sel:
                ScriptBlockText: Test
                Path: Test
            condition: sel
    """)


@pytest.fixture
def raw_access_thread_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Raw Access Thread Test
        status: test
        logsource:
            category: raw_access_thread
            product: windows
        detection:
            sel:
                Image: test.exe
            condition: sel
    """)


@pytest.fixture
def registry_add_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Registry Add Test
        status: test
        logsource:
            category: registry_add
            product: windows
        detection:
            sel:
                TargetObject: test.exe
            condition: sel
    """)


@pytest.fixture
def registry_delete_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Registry Delete Test
        status: test
        logsource:
            category: registry_delete
            product: windows
        detection:
            sel:
                TargetObject: test.exe
            condition: sel
    """)


@pytest.fixture
def registry_event_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Registry Event Test
        status: test
        logsource:
            category: registry_event
            product: windows
        detection:
            sel:
                Image: test.exe
            condition: sel
    """)


@pytest.fixture
def registry_rename_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Registry Rename Test
        status: test
        logsource:
            category: registry_rename
            product: windows
        detection:
            sel:
                TargetObject: test.exe
            condition: sel
    """)


@pytest.fixture
def registry_set_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Registry Set Test
        status: test
        logsource:
            category: registry_set
            product: windows
        detection:
            sel:
                TargetObject: test.exe
            condition: sel
    """)


@pytest.fixture
def sysmon_error_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Sysmon Error Test
        status: test
        logsource:
            category: sysmon_error
            product: windows
        detection:
            sel:
                Description: a error is here
            condition: sel
    """)


@pytest.fixture
def sysmon_status_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Sysmon Status Test
        status: test
        logsource:
            category: sysmon_status
            product: windows
        detection:
            sel:
                State: Test
            condition: sel
    """)


@pytest.fixture
def webserver_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: Webserver Test
        status: test
        logsource:
            category: webserver
            product: windows
        detection:
            sel:
                cs-uri-query: /test/test.exe
                cs-method: GET
                sc-status: Test
                cs-user-agent: Test-UA
                cs-referer: Test-Referer
            condition: sel
    """)


@pytest.fixture
def wmi_event_sigma_rule():
    return SigmaCollection.from_yaml("""
        title: WMI Event Test
        status: test
        logsource:
            category: wmi_event
            product: windows
        detection:
            sel:
                EventID: 4711
                Destination: Test
            condition: sel
    """)
