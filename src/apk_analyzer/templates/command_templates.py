"""
Component-type-aware command templates for Phase 2B execution guidance generation.

Templates serve as guardrails - they provide correct patterns that the LLM can adapt,
rather than rigid structures that must be followed exactly.

Each template includes:
- component_type: Validates that the correct template is used (activity/service/receiver)
- required_vars: Variables that must be provided
- optional_vars: Variables that can enhance the command
- verification_template: Pattern for verifying successful execution
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class ComponentType(Enum):
    """Android component types."""
    ACTIVITY = "activity"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"
    ANY = "any"  # For commands not tied to a specific component type


class TemplateCategory(Enum):
    """Threat categories for grouping templates."""
    COMMON = "common"
    SURVEILLANCE_AUDIO = "surveillance_audio"
    SURVEILLANCE_CAMERA = "surveillance_camera"
    SURVEILLANCE_SCREEN = "surveillance_screen"
    C2_NETWORK = "c2_network"
    OVERLAY_PHISHING = "overlay_phishing"
    DATA_EXFILTRATION = "data_exfiltration"
    SMS = "sms"
    RANSOMWARE = "ransomware"
    PERSISTENCE = "persistence"


@dataclass
class CommandTemplate:
    """
    A template for generating ADB/Frida commands with component-type validation.

    Attributes:
        template_id: Unique identifier for the template
        component_type: Which component types this template is valid for
        categories: Threat categories this template belongs to
        template: The command template with {variable} placeholders
        required_vars: Variables that must be provided
        optional_vars: Optional variables with defaults
        verification_template: Template for verifying execution success
        description: Human-readable description of what this template does
        notes: Additional guidance for the LLM on when/how to use this template
    """
    template_id: str
    component_type: ComponentType
    categories: List[TemplateCategory]
    template: str
    required_vars: List[str]
    optional_vars: Dict[str, str] = field(default_factory=dict)
    verification_template: Optional[str] = None
    description: str = ""
    notes: str = ""

    def is_valid_for_component(self, component_type: str) -> bool:
        """Check if this template can be used for the given component type."""
        if self.component_type == ComponentType.ANY:
            return True
        return self.component_type.value == component_type.lower()

    def get_missing_vars(self, provided_vars: Dict[str, Any]) -> Set[str]:
        """Return the set of required variables that are missing."""
        return set(self.required_vars) - set(provided_vars.keys())

    def fill(self, vars: Dict[str, Any]) -> Optional[str]:
        """
        Fill in the template with provided variables.
        Returns None if required variables are missing.
        """
        missing = self.get_missing_vars(vars)
        if missing:
            return None

        # Merge with optional defaults
        merged_vars = {**self.optional_vars, **vars}

        try:
            return self.template.format(**merged_vars)
        except KeyError:
            return None

    def fill_verification(self, vars: Dict[str, Any]) -> Optional[str]:
        """Fill in the verification template."""
        if not self.verification_template:
            return None

        merged_vars = {**self.optional_vars, **vars}

        try:
            return self.verification_template.format(**merged_vars)
        except KeyError:
            return None


# =============================================================================
# COMMON TEMPLATES - Used across multiple threat categories
# =============================================================================

TEMPLATE_GRANT_PERMISSION = CommandTemplate(
    template_id="grant_permission",
    component_type=ComponentType.ANY,
    categories=[TemplateCategory.COMMON],
    template="adb shell pm grant {package_name} {permission}",
    required_vars=["package_name", "permission"],
    verification_template="adb shell dumpsys package {package_name} | grep {permission}",
    description="Grant a runtime permission to the app",
    notes="Use for permissions like RECORD_AUDIO, CAMERA, READ_CONTACTS, etc.",
)

TEMPLATE_START_ACTIVITY = CommandTemplate(
    template_id="start_activity",
    component_type=ComponentType.ACTIVITY,
    categories=[TemplateCategory.COMMON],
    template="adb shell am start -n {package_name}/{component_name}",
    required_vars=["package_name", "component_name"],
    verification_template="adb shell dumpsys activity activities | grep {component_name}",
    description="Start an Activity component",
    notes="Use -a to add action, -d for data URI, --es for string extras",
)

TEMPLATE_START_ACTIVITY_WITH_ACTION = CommandTemplate(
    template_id="start_activity_with_action",
    component_type=ComponentType.ACTIVITY,
    categories=[TemplateCategory.COMMON],
    template="adb shell am start -n {package_name}/{component_name} -a {action}",
    required_vars=["package_name", "component_name", "action"],
    verification_template="adb shell dumpsys activity activities | grep {component_name}",
    description="Start an Activity with a specific intent action",
)

TEMPLATE_START_SERVICE = CommandTemplate(
    template_id="start_service",
    component_type=ComponentType.SERVICE,
    categories=[TemplateCategory.COMMON],
    template="adb shell am start-service -n {package_name}/{component_name}",
    required_vars=["package_name", "component_name"],
    verification_template="adb shell dumpsys activity services | grep {component_name}",
    description="Start a Service component",
    notes="For foreground services on Android 8+, use start_foreground_service instead",
)

TEMPLATE_START_FOREGROUND_SERVICE = CommandTemplate(
    template_id="start_foreground_service",
    component_type=ComponentType.SERVICE,
    categories=[TemplateCategory.COMMON, TemplateCategory.SURVEILLANCE_AUDIO],
    template="adb shell am start-foreground-service -n {package_name}/{component_name}",
    required_vars=["package_name", "component_name"],
    verification_template="adb shell dumpsys activity services | grep {component_name}",
    description="Start a foreground service (Android 8+)",
    notes="Required for services that use RECORD_AUDIO, CAMERA, FOREGROUND_SERVICE_*",
)

TEMPLATE_SEND_BROADCAST = CommandTemplate(
    template_id="send_broadcast",
    component_type=ComponentType.RECEIVER,
    categories=[TemplateCategory.COMMON],
    template="adb shell am broadcast -n {package_name}/{component_name}",
    required_vars=["package_name", "component_name"],
    verification_template="adb logcat -d -t 30 | grep {component_short_name}",
    optional_vars={"component_short_name": "BroadcastReceiver"},
    description="Send a broadcast to a specific receiver",
    notes="Add -a for action, --es for string extras",
)

TEMPLATE_SEND_BROADCAST_WITH_ACTION = CommandTemplate(
    template_id="send_broadcast_with_action",
    component_type=ComponentType.RECEIVER,
    categories=[TemplateCategory.COMMON],
    template="adb shell am broadcast -a {action} -n {package_name}/{component_name}",
    required_vars=["package_name", "component_name", "action"],
    verification_template="adb logcat -d -t 30 | grep {component_short_name}",
    optional_vars={"component_short_name": "BroadcastReceiver"},
    description="Send a broadcast with a specific action",
)

TEMPLATE_FORCE_STOP = CommandTemplate(
    template_id="force_stop",
    component_type=ComponentType.ANY,
    categories=[TemplateCategory.COMMON],
    template="adb shell am force-stop {package_name}",
    required_vars=["package_name"],
    description="Force stop the app before triggering behavior",
    notes="Use to ensure clean state before testing",
)


# =============================================================================
# SURVEILLANCE - AUDIO TEMPLATES
# =============================================================================

TEMPLATE_AUDIO_CHECK_FILE = CommandTemplate(
    template_id="audio_check_file",
    component_type=ComponentType.ANY,
    categories=[TemplateCategory.SURVEILLANCE_AUDIO],
    template="adb shell ls -la {audio_file_path}",
    required_vars=["audio_file_path"],
    verification_template="adb shell ls {audio_file_path}",
    description="Check if an audio recording file exists",
    notes="Use after triggering the recording service/activity",
)

TEMPLATE_AUDIO_PULL_FILE = CommandTemplate(
    template_id="audio_pull_file",
    component_type=ComponentType.ANY,
    categories=[TemplateCategory.SURVEILLANCE_AUDIO],
    template="adb pull {audio_file_path} evidence/",
    required_vars=["audio_file_path"],
    description="Pull recorded audio file for analysis",
    notes="Run 'mkdir -p evidence' first if needed",
)

TEMPLATE_AUDIO_FRIDA_HOOK = CommandTemplate(
    template_id="audio_frida_hook",
    component_type=ComponentType.SERVICE,
    categories=[TemplateCategory.SURVEILLANCE_AUDIO],
    template="frida -U -f {package_name} -l hooks/media_recorder.js --no-pause",
    required_vars=["package_name"],
    optional_vars={"hook_script": "hooks/media_recorder.js"},
    description="Hook MediaRecorder to observe audio capture calls",
    notes="Requires pre-written Frida script that hooks setAudioSource, start, stop",
)


# =============================================================================
# SURVEILLANCE - CAMERA TEMPLATES
# =============================================================================

TEMPLATE_CAMERA_CHECK_FILE = CommandTemplate(
    template_id="camera_check_file",
    component_type=ComponentType.ANY,
    categories=[TemplateCategory.SURVEILLANCE_CAMERA],
    template="adb shell ls -la {camera_file_path}",
    required_vars=["camera_file_path"],
    verification_template="adb shell ls {camera_file_path}",
    description="Check if a captured image/video exists",
)

TEMPLATE_CAMERA_PULL_FILE = CommandTemplate(
    template_id="camera_pull_file",
    component_type=ComponentType.ANY,
    categories=[TemplateCategory.SURVEILLANCE_CAMERA],
    template="adb pull {camera_file_path} evidence/",
    required_vars=["camera_file_path"],
    description="Pull captured image/video for analysis",
)


# =============================================================================
# SURVEILLANCE - SCREEN CAPTURE TEMPLATES
# =============================================================================

TEMPLATE_SCREEN_CAPTURE_PERMISSION = CommandTemplate(
    template_id="screen_capture_permission",
    component_type=ComponentType.ANY,
    categories=[TemplateCategory.SURVEILLANCE_SCREEN],
    template="adb shell appops set {package_name} PROJECT_MEDIA allow",
    required_vars=["package_name"],
    description="Grant media projection permission",
    notes="MediaProjection requires user consent in production; this bypasses for testing",
)


# =============================================================================
# C2 / NETWORK TEMPLATES
# =============================================================================

TEMPLATE_C2_NETWORK_CHECK = CommandTemplate(
    template_id="c2_network_check",
    component_type=ComponentType.ANY,
    categories=[TemplateCategory.C2_NETWORK],
    template="adb shell netstat -an | grep {c2_port}",
    required_vars=["c2_port"],
    optional_vars={"c2_port": "443"},
    description="Check for network connections on C2 port",
)

TEMPLATE_C2_DNS_MONITOR = CommandTemplate(
    template_id="c2_dns_monitor",
    component_type=ComponentType.ANY,
    categories=[TemplateCategory.C2_NETWORK],
    template="adb logcat -d -s NetworkMonitor DnsResolver | grep -i {c2_domain}",
    required_vars=["c2_domain"],
    description="Monitor DNS queries for C2 domain",
)

TEMPLATE_C2_FRIDA_HOOK_SOCKET = CommandTemplate(
    template_id="c2_frida_hook_socket",
    component_type=ComponentType.ANY,
    categories=[TemplateCategory.C2_NETWORK],
    template="frida -U -f {package_name} -l hooks/network_socket.js --no-pause 2>&1 | tee evidence/c2_traffic.log",
    required_vars=["package_name"],
    description="Hook socket operations to capture C2 communication",
    notes="Requires pre-written Frida script for socket hooks",
)


# =============================================================================
# OVERLAY / PHISHING TEMPLATES
# =============================================================================

TEMPLATE_OVERLAY_PERMISSION = CommandTemplate(
    template_id="overlay_permission",
    component_type=ComponentType.ANY,
    categories=[TemplateCategory.OVERLAY_PHISHING],
    template="adb shell appops set {package_name} SYSTEM_ALERT_WINDOW allow",
    required_vars=["package_name"],
    description="Grant overlay (SYSTEM_ALERT_WINDOW) permission",
    notes="Required for apps that draw overlay windows",
)

TEMPLATE_OVERLAY_CHECK_ACTIVE = CommandTemplate(
    template_id="overlay_check_active",
    component_type=ComponentType.ANY,
    categories=[TemplateCategory.OVERLAY_PHISHING],
    template="adb shell dumpsys window windows | grep -E 'mOwnerPackage={package_name}'",
    required_vars=["package_name"],
    description="Check if app has active overlay windows",
)


# =============================================================================
# DATA EXFILTRATION TEMPLATES
# =============================================================================

TEMPLATE_EXFIL_CONTACTS = CommandTemplate(
    template_id="exfil_check_contacts_access",
    component_type=ComponentType.ANY,
    categories=[TemplateCategory.DATA_EXFILTRATION],
    template="adb shell content query --uri content://contacts/people --projection display_name | head -5",
    required_vars=[],
    description="Verify contacts are accessible (as malware would see them)",
)

TEMPLATE_EXFIL_SMS = CommandTemplate(
    template_id="exfil_check_sms_access",
    component_type=ComponentType.ANY,
    categories=[TemplateCategory.DATA_EXFILTRATION],
    template="adb shell content query --uri content://sms --projection body | head -5",
    required_vars=[],
    description="Verify SMS messages are accessible",
)


# =============================================================================
# SMS TEMPLATES
# =============================================================================

TEMPLATE_SMS_SEND = CommandTemplate(
    template_id="sms_send_test",
    component_type=ComponentType.ANY,
    categories=[TemplateCategory.SMS],
    template="adb shell am start -a android.intent.action.SENDTO -d 'sms:{phone_number}' --es sms_body '{message}'",
    required_vars=["phone_number", "message"],
    description="Simulate SMS send intent (opens SMS app, doesn't actually send)",
    notes="For actual send testing, use SmsManager Frida hook",
)


# =============================================================================
# PERSISTENCE TEMPLATES
# =============================================================================

TEMPLATE_PERSISTENCE_BOOT_RECEIVER = CommandTemplate(
    template_id="persistence_boot_complete",
    component_type=ComponentType.RECEIVER,
    categories=[TemplateCategory.PERSISTENCE],
    template="adb shell am broadcast -a android.intent.action.BOOT_COMPLETED -n {package_name}/{receiver_name}",
    required_vars=["package_name", "receiver_name"],
    verification_template="adb shell dumpsys activity services | grep {package_name}",
    description="Simulate boot complete broadcast to trigger persistence",
    notes="May need -p flag with package name for some receivers",
)


# =============================================================================
# TEMPLATE REGISTRY
# =============================================================================

COMMAND_TEMPLATES: List[CommandTemplate] = [
    # Common
    TEMPLATE_GRANT_PERMISSION,
    TEMPLATE_START_ACTIVITY,
    TEMPLATE_START_ACTIVITY_WITH_ACTION,
    TEMPLATE_START_SERVICE,
    TEMPLATE_START_FOREGROUND_SERVICE,
    TEMPLATE_SEND_BROADCAST,
    TEMPLATE_SEND_BROADCAST_WITH_ACTION,
    TEMPLATE_FORCE_STOP,
    # Surveillance - Audio
    TEMPLATE_AUDIO_CHECK_FILE,
    TEMPLATE_AUDIO_PULL_FILE,
    TEMPLATE_AUDIO_FRIDA_HOOK,
    # Surveillance - Camera
    TEMPLATE_CAMERA_CHECK_FILE,
    TEMPLATE_CAMERA_PULL_FILE,
    # Surveillance - Screen
    TEMPLATE_SCREEN_CAPTURE_PERMISSION,
    # C2/Network
    TEMPLATE_C2_NETWORK_CHECK,
    TEMPLATE_C2_DNS_MONITOR,
    TEMPLATE_C2_FRIDA_HOOK_SOCKET,
    # Overlay/Phishing
    TEMPLATE_OVERLAY_PERMISSION,
    TEMPLATE_OVERLAY_CHECK_ACTIVE,
    # Data Exfiltration
    TEMPLATE_EXFIL_CONTACTS,
    TEMPLATE_EXFIL_SMS,
    # SMS
    TEMPLATE_SMS_SEND,
    # Persistence
    TEMPLATE_PERSISTENCE_BOOT_RECEIVER,
]

# Index by template_id for quick lookup
_TEMPLATE_BY_ID: Dict[str, CommandTemplate] = {t.template_id: t for t in COMMAND_TEMPLATES}

# Index by category
_TEMPLATES_BY_CATEGORY: Dict[TemplateCategory, List[CommandTemplate]] = {}
for template in COMMAND_TEMPLATES:
    for category in template.categories:
        if category not in _TEMPLATES_BY_CATEGORY:
            _TEMPLATES_BY_CATEGORY[category] = []
        _TEMPLATES_BY_CATEGORY[category].append(template)


# =============================================================================
# PUBLIC FUNCTIONS
# =============================================================================

def get_template_by_id(template_id: str) -> Optional[CommandTemplate]:
    """Get a template by its ID."""
    return _TEMPLATE_BY_ID.get(template_id)


def get_templates_for_category(category: TemplateCategory | str) -> List[CommandTemplate]:
    """Get all templates for a threat category."""
    if isinstance(category, str):
        try:
            category = TemplateCategory(category.lower())
        except ValueError:
            return []
    return _TEMPLATES_BY_CATEGORY.get(category, [])


def get_templates_for_component_type(component_type: str) -> List[CommandTemplate]:
    """Get all templates valid for a component type."""
    return [t for t in COMMAND_TEMPLATES if t.is_valid_for_component(component_type)]


def validate_template_vars(
    template_id: str,
    provided_vars: Dict[str, Any],
    component_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Validate that provided variables are sufficient for a template.

    Returns:
        Dict with 'valid', 'missing_vars', 'component_mismatch', 'template'
    """
    template = get_template_by_id(template_id)
    if not template:
        return {
            "valid": False,
            "error": f"Unknown template: {template_id}",
            "template": None,
        }

    result = {
        "valid": True,
        "template": template,
        "missing_vars": [],
        "component_mismatch": False,
    }

    # Check component type
    if component_type and not template.is_valid_for_component(component_type):
        result["valid"] = False
        result["component_mismatch"] = True
        result["error"] = (
            f"Template '{template_id}' is for {template.component_type.value}, "
            f"but component is {component_type}"
        )

    # Check required vars
    missing = template.get_missing_vars(provided_vars)
    if missing:
        result["valid"] = False
        result["missing_vars"] = list(missing)
        result["error"] = f"Missing required variables: {missing}"

    return result


def fill_template(
    template_id: str,
    vars: Dict[str, Any],
    component_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Fill a template with variables, with validation.

    Returns:
        Dict with 'command', 'verification', 'valid', 'error'
    """
    validation = validate_template_vars(template_id, vars, component_type)
    if not validation["valid"]:
        return {
            "command": None,
            "verification": None,
            "valid": False,
            "error": validation.get("error"),
        }

    template = validation["template"]
    command = template.fill(vars)
    verification = template.fill_verification(vars)

    return {
        "command": command,
        "verification": verification,
        "valid": True,
        "template_id": template_id,
        "description": template.description,
    }
