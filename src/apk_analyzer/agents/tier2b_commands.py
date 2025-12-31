"""
Phase 2B: Command Generation Agent.

This agent generates concrete execution commands from Phase 2A driver requirements.
It uses:
- ValueHintsBundle for grounded command generation
- Command templates as guardrails
- Relevant seed's Tier1 output for context

It focuses on accurate, evidence-grounded command generation.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from apk_analyzer.agents.base import LLMClient
from apk_analyzer.analyzers.value_hints_builder import ValueHintsBundle
from apk_analyzer.models.tier2_phases import (
    DriverRequirement,
    ExecutionStep,
    Phase2BOutput,
)
from apk_analyzer.observability.logger import EventLogger
from apk_analyzer.templates.command_templates import (
    COMMAND_TEMPLATES,
    CommandTemplate,
    TemplateCategory,
    get_templates_for_category,
)
from apk_analyzer.utils.llm_json import coerce_llm_dict, describe_llm_failure


class Tier2BCommandsAgent:
    """
    Phase 2B agent for command generation.

    Generates concrete execution steps from:
    - Driver requirements (from Phase 2A)
    - ValueHintsBundle (consolidated hints)
    - Relevant seed's Tier1 output
    - Command templates (as guardrails)
    """

    def __init__(
        self,
        prompt_path: str | Path,
        llm_client: Optional[LLMClient] = None,
        model: Optional[str] = None,
        event_logger: EventLogger | None = None,
    ) -> None:
        self.prompt_path = Path(prompt_path)
        self.llm_client = llm_client
        self.model = model
        self.event_logger = event_logger
        self.prompt = self.prompt_path.read_text(encoding="utf-8") if self.prompt_path.exists() else ""

    def run(
        self,
        driver_requirement: DriverRequirement,
        value_hints: ValueHintsBundle,
        seed_tier1: Dict[str, Any],
        package_name: str,
    ) -> Phase2BOutput:
        """
        Generate execution commands for a single driver requirement.

        Args:
            driver_requirement: From Phase 2A
            value_hints: Consolidated hints from extractors
            seed_tier1: The relevant seed's Tier1 output
            package_name: APK package name

        Returns:
            Phase2BOutput with execution steps
        """
        req_id = driver_requirement.requirement_id
        seed_id = driver_requirement.seed_id

        if not self.llm_client:
            if self.event_logger:
                self.event_logger.log(
                    "llm.fallback",
                    llm_step="tier2b",
                    requirement_id=req_id,
                    seed_id=seed_id,
                    error_type="disabled",
                )
            return self._build_fallback(driver_requirement, value_hints, package_name, "LLM disabled")

        # Build payload for LLM
        payload = self._build_payload(driver_requirement, value_hints, seed_tier1, package_name)

        response = self.llm_client.complete(self.prompt, payload, model=self.model)

        required_keys = ("steps",)
        fallback_dict = self._build_fallback_dict(driver_requirement, "LLM output invalid")

        result_dict = coerce_llm_dict(response, fallback_dict, required_keys=required_keys)

        if result_dict is fallback_dict:
            if self.event_logger:
                info = describe_llm_failure(response, required_keys=required_keys)
                self.event_logger.log(
                    "llm.fallback",
                    llm_step="tier2b",
                    requirement_id=req_id,
                    seed_id=seed_id,
                    **(info or {"error_type": "invalid_output"}),
                )
            return self._build_fallback(driver_requirement, value_hints, package_name, "LLM output invalid")

        return self._parse_output(result_dict, driver_requirement)

    def _build_payload(
        self,
        driver_req: DriverRequirement,
        value_hints: ValueHintsBundle,
        seed_tier1: Dict[str, Any],
        package_name: str,
    ) -> Dict[str, Any]:
        """Build LLM payload with all context.

        Supports both legacy (seed_tier1) and new (seed_analysis with execution_path) formats.
        """
        # Get relevant templates for this threat category
        category = driver_req.threat_category
        templates = get_templates_for_category(category)
        if not templates:
            templates = get_templates_for_category(TemplateCategory.COMMON)

        template_info = [
            {
                "template_id": t.template_id,
                "component_type": t.component_type.value,
                "template": t.template,
                "required_vars": t.required_vars,
                "verification_template": t.verification_template,
                "description": t.description,
            }
            for t in templates
        ]

        # Build seed_analysis for new format (includes execution_path)
        # Check if we have execution_path (new format from seed_composer)
        if "execution_path" in seed_tier1:
            # New method-centric format
            seed_analysis = {
                "seed_id": seed_tier1.get("seed_id", driver_req.seed_id),
                "api_category": seed_tier1.get("api_category", ""),
                "sink_api": seed_tier1.get("sink_api", ""),
                "execution_path": seed_tier1.get("execution_path", []),
                "all_constraints": seed_tier1.get("all_constraints", []),
                "required_permissions": seed_tier1.get("required_permissions", []),
                "all_required_inputs": seed_tier1.get("all_required_inputs", []),
                "component_context": seed_tier1.get("component_context", {}),
                "reachability": seed_tier1.get("reachability", {}),
            }
        else:
            # Legacy format - wrap in execution_path-like structure
            seed_analysis = {
                "seed_id": seed_tier1.get("seed_id", driver_req.seed_id),
                "api_category": seed_tier1.get("api_category", ""),
                "sink_api": "",
                # Create a single-method execution_path from legacy data
                "execution_path": [
                    {
                        "method": seed_tier1.get("trigger_surface", {}).get("entrypoint_method", ""),
                        "summary": seed_tier1.get("function_summary", ""),
                        "data_flow": [],
                        "trigger_info": {
                            "is_entrypoint": True,
                            "component_type": seed_tier1.get("trigger_surface", {}).get("component_type"),
                            "component_name": seed_tier1.get("trigger_surface", {}).get("component_name"),
                        },
                        "constraints": seed_tier1.get("path_constraints", []),
                        "facts": seed_tier1.get("facts", []),
                    }
                ] if seed_tier1.get("trigger_surface") else [],
                "all_constraints": seed_tier1.get("path_constraints", []),
                "required_permissions": [
                    inp for inp in seed_tier1.get("required_inputs", [])
                    if inp.get("type") == "permission"
                ],
                "all_required_inputs": seed_tier1.get("required_inputs", []),
                "component_context": seed_tier1.get("trigger_surface", {}),
                "reachability": {},
            }

        return {
            "requirement_id": driver_req.requirement_id,
            "seed_id": driver_req.seed_id,
            "package_name": package_name,
            "driver_requirement": driver_req.to_dict(),
            "value_hints": value_hints.to_dict(),
            # Use seed_analysis (new name matching prompt)
            "seed_analysis": seed_analysis,
            # Keep seed_tier1 for backward compatibility
            "seed_tier1": {
                "function_summary": seed_tier1.get("function_summary", ""),
                "trigger_surface": seed_tier1.get("trigger_surface", {}),
                "path_constraints": seed_tier1.get("path_constraints", []),
                "required_inputs": seed_tier1.get("required_inputs", []),
                "observable_effects": seed_tier1.get("observable_effects", []),
                "observable_effects_detail": seed_tier1.get("observable_effects_detail", []),
                "facts": seed_tier1.get("facts", []),
            },
            "available_templates": template_info,
        }

    def _parse_output(
        self,
        result: Dict[str, Any],
        driver_req: DriverRequirement,
    ) -> Phase2BOutput:
        """Parse LLM output into Phase2BOutput."""
        steps = []
        for step_data in result.get("steps", []):
            step = ExecutionStep(
                step_id=step_data.get("step_id", f"step_{len(steps)}"),
                type=step_data.get("type", "adb"),
                description=step_data.get("description", ""),
                command=step_data.get("command"),
                verify=step_data.get("verify"),
                evidence_citation=step_data.get("evidence_citation"),
                notes=step_data.get("notes"),
                template_id=step_data.get("template_id"),
                template_vars=step_data.get("template_vars", {}),
            )
            steps.append(step)

        manual_steps = []
        for step_data in result.get("manual_steps", []):
            step = ExecutionStep(
                step_id=step_data.get("step_id", f"manual_{len(manual_steps)}"),
                type="manual",
                description=step_data.get("description", ""),
                command=step_data.get("command"),
                notes=step_data.get("notes"),
            )
            manual_steps.append(step)

        return Phase2BOutput(
            requirement_id=driver_req.requirement_id,
            seed_id=driver_req.seed_id,
            steps=steps,
            manual_steps=manual_steps,
            automation_feasibility=result.get("automation_feasibility", driver_req.automation_feasibility),
            warnings=result.get("warnings", []),
        )

    def _build_fallback(
        self,
        driver_req: DriverRequirement,
        value_hints: ValueHintsBundle,
        package_name: str,
        reason: str,
    ) -> Phase2BOutput:
        """Build fallback Phase2BOutput using templates directly."""
        steps = []
        manual_steps = []

        component_name = driver_req.component_name
        component_type = driver_req.component_type.lower()

        if not component_name:
            # Can't generate anything without component name
            manual_steps.append(ExecutionStep(
                step_id="manual_identify_component",
                type="manual",
                description="Identify target component from static analysis",
                command=f"MANUAL: {reason}. Review code to find entrypoint.",
            ))
            return Phase2BOutput(
                requirement_id=driver_req.requirement_id,
                seed_id=driver_req.seed_id,
                steps=steps,
                manual_steps=manual_steps,
                automation_feasibility="manual_investigation_required",
                warnings=[reason],
            )

        # Generate basic trigger step based on component type
        if component_type == "service":
            steps.append(ExecutionStep(
                step_id="trigger_service",
                type="adb",
                description=f"Start service {component_name}",
                command=f"adb shell am start-service -n {package_name}/{component_name}",
                template_id="start_service",
                template_vars={"package_name": package_name, "component_name": component_name},
            ))
        elif component_type == "activity":
            steps.append(ExecutionStep(
                step_id="trigger_activity",
                type="adb",
                description=f"Start activity {component_name}",
                command=f"adb shell am start -n {package_name}/{component_name}",
                template_id="start_activity",
                template_vars={"package_name": package_name, "component_name": component_name},
            ))
        elif component_type == "receiver":
            steps.append(ExecutionStep(
                step_id="trigger_receiver",
                type="adb",
                description=f"Send broadcast to {component_name}",
                command=f"adb shell am broadcast -n {package_name}/{component_name}",
                template_id="send_broadcast",
                template_vars={"package_name": package_name, "component_name": component_name},
            ))
        else:
            manual_steps.append(ExecutionStep(
                step_id="manual_trigger",
                type="manual",
                description=f"Trigger unknown component type: {component_type}",
                command=f"MANUAL: Determine how to trigger {component_name}",
            ))

        # Add verification step if we have file hints
        if value_hints.file_hints:
            file_hint = value_hints.file_hints[0]
            if file_hint.resolved_path:
                steps.append(ExecutionStep(
                    step_id="verify_file",
                    type="adb",
                    description="Check for created file",
                    command=f"adb shell ls -la {file_hint.resolved_path}",
                    verify={"command": f"adb shell ls {file_hint.resolved_path}"},
                ))

        return Phase2BOutput(
            requirement_id=driver_req.requirement_id,
            seed_id=driver_req.seed_id,
            steps=steps,
            manual_steps=manual_steps,
            automation_feasibility="partial" if manual_steps else "full",
            warnings=[f"Fallback generation: {reason}"],
        )

    def _build_fallback_dict(
        self,
        driver_req: DriverRequirement,
        reason: str,
    ) -> Dict[str, Any]:
        """Build fallback dict for coerce_llm_dict."""
        return {
            "requirement_id": driver_req.requirement_id,
            "seed_id": driver_req.seed_id,
            "steps": [],
            "manual_steps": [],
            "automation_feasibility": "manual_investigation_required",
            "warnings": [reason],
        }
