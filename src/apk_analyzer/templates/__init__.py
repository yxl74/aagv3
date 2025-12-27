"""Command templates for execution guidance generation."""

from .command_templates import (
    CommandTemplate,
    TemplateCategory,
    COMMAND_TEMPLATES,
    get_templates_for_category,
    get_template_by_id,
    validate_template_vars,
    fill_template,
)

__all__ = [
    "CommandTemplate",
    "TemplateCategory",
    "COMMAND_TEMPLATES",
    "get_templates_for_category",
    "get_template_by_id",
    "validate_template_vars",
    "fill_template",
]
