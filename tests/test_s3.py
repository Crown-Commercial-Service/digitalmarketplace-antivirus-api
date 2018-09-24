import pytest

from app.s3 import _filename_from_content_disposition


@pytest.mark.parametrize("cd_string,expected_output", (
    ("a", None,),
    ("attachment; filename=abcd3_ .pdf ", "abcd3_ .pdf",),
    ('bla; bla; filename="things...other...things.PNG";', "things...other...things.PNG",),
    (';filename= 8765432', " 8765432",),
))
def test_filename_from_content_disposition(cd_string, expected_output):
    assert _filename_from_content_disposition(cd_string) == expected_output
