from jpdfrsc.core.pdf_document import parse_scalar
import pikepdf


def test_scalar_parser():
    assert parse_scalar("true") is True
    assert parse_scalar("null") is None
    assert parse_scalar("42") == 42
    assert parse_scalar("3.5") == 3.5
    assert str(parse_scalar("/Example")) == "/Example"
    assert str(parse_scalar("(hello)")) == "hello"
