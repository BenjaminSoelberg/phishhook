from dataclasses import dataclass, field

from marshmallow_dataclass import add_schema


@add_schema
@dataclass(eq=True, frozen=True)
class Brand:
    brand: str
    known_domains: list[str]
    trigger_words: list[str]
    score_words: list[str]
    ignored_domains: list[str] = list
    enabled: bool = True

    class Meta:
        ordered = True
