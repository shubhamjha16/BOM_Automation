"""A table citation already names its element, so prose must not name it twice; field tables keep
guideline order."""

from __future__ import annotations

from app.services.catalogue.loader import all_catalogues
from app.services.catalogue.types import clause_with_label, label_repeats_clause


def test_repeated_name_is_not_printed_twice() -> None:
    clause = "9.3 Table 10: Software Dependencies"
    assert label_repeats_clause(clause, "Software Dependencies")
    assert clause_with_label(clause, "Software Dependencies") == clause


def test_plain_clause_still_gets_its_label() -> None:
    assert clause_with_label("4.2(1)", "Component Name") == "4.2(1) Component Name"
    assert not label_repeats_clause("4.2(1)", "")


def test_trailing_note_on_label_is_ignored() -> None:
    assert label_repeats_clause("8.3 Table 9: Keys - id", "Keys - id (product)")


def test_no_catalogue_element_prints_its_name_twice() -> None:
    for catalogue in all_catalogues().values():
        for element in catalogue.elements:
            text = clause_with_label(element.clause, element.label)
            assert text.lower().count(element.label.lower()) <= 1, text


async def test_field_report_is_in_guideline_order() -> None:
    from types import SimpleNamespace

    from app.controllers.submissionController import field_report

    elements = list(all_catalogues()["cbom"].elements)
    rows = [
        SimpleNamespace(
            element_key=el.key, clause=el.clause, verdict="present", populated=1, total=1,
            coverage=1.0, detail=None, consumer_action=None,
        )
        for el in sorted(elements, key=lambda e: e.clause)
    ]

    class Lanes:
        async def for_submission(self, _id):
            return [SimpleNamespace(id=1, lane="cbom", score=90, verdict="pass")]

        async def verdicts_for(self, _id):
            return rows

    import uuid

    report = await field_report(Lanes(), uuid.uuid4(), "cbom")
    assert [f["element_key"] for f in report["fields"]] == [el.key for el in elements]
