from dataclasses import dataclass, field


@dataclass
class Section:
    key:           str
    label:         str
    hint:          str
    content_lines: list[str] = field(default_factory=list)
    actions:       list[str] = field(default_factory=list)