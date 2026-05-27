from dataclasses import dataclass, field


@dataclass
class FieldMeta:
    attr_path: str
    label:     str
    editable:  bool
    line_idx:  int


@dataclass
class Section:
    key:           str
    label:         str
    hint:          str
    content_lines: list[str]         = field(default_factory=list)
    actions:       list[str]         = field(default_factory=list)
    field_map:     list[FieldMeta]   = field(default_factory=list)