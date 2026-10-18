"""Regression tests: an S3 audit that could not run must not report "clean".

Defects:
  * Eight bare `except:` clauses in check-permissions.py (lines 51, 107, 132,
    149, 178, 191, 219, 238 before the fix). Every failure -- AccessDenied,
    throttling, a malformed policy, a KeyError raised by the parsing logic
    itself -- was swallowed and reported as the benign "does not have a
    policy", or silently produced nothing. A bucket that was never audited
    therefore looked like a bucket with no issues, and the final summary read
    "No permission issues found."
  * Separately, the file had an IndentationError at line 74 and an undefined
    `session` at line 37, so it could not be imported or run at all.

Fails on the original file, passes on the patched one.
"""
import importlib.util
import io
import json
import pathlib
import sys
import types

import pytest
from botocore.exceptions import ClientError

# Imported by check-permissions.py but not needed for these tests and not
# installed here; a normal environment installs them from requirements.txt.
for _name in ("pdfkit", "html2text"):
    if _name not in sys.modules:
        _m = types.ModuleType(_name)
        _m.from_file = lambda *a, **k: None
        sys.modules[_name] = _m

SRC = pathlib.Path(__file__).resolve().parents[1] / "check-permissions.py"

LOG_BUCKET = "audit-logs"

# A policy that satisfies every ASVS check in the auditor, so the "clean" test
# is testing the auditor rather than my fixture.
COMPLIANT_POLICY = {
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "s3:*",
            "Condition": {
                "ArnLike": {
                    "aws:PrincipalArn": "arn:aws:iam::123456789012:role/auditor",
                    "aws:Referer": "https://example.test/*",
                },
                "StringLike": {"aws:SecureTransport": "true"},
                "IpAddress": {"aws:SourceIp": "10.0.0.0/8"},
            },
        }
    ]
}


def client_error(code, op="GetBucketPolicy"):
    return ClientError({"Error": {"Code": code, "Message": f"{code} for {op}"}}, op)


class FakeS3:
    """Minimal S3 client: fully compliant unless an error is injected.

    Injected failures apply to the audited buckets only. The access-log target
    bucket always answers, because ASVS 3.1.10 reads its policy from a block
    that has no error handling at all (unchanged by this patch).
    """

    def __init__(self, buckets=("audit-target",), policy_exc=None, lifecycle_exc=None,
                 policy=None, log_bucket=LOG_BUCKET):
        self.buckets = list(buckets)
        self.policy_exc = policy_exc
        self.lifecycle_exc = lifecycle_exc
        self.policy = COMPLIANT_POLICY if policy is None else policy
        self.log_bucket = log_bucket

    def list_buckets(self):
        return {"Buckets": [{"Name": b} for b in self.buckets]}

    def get_bucket_policy(self, Bucket):
        if Bucket == self.log_bucket:
            return {"Policy": json.dumps(COMPLIANT_POLICY)}
        if self.policy_exc:
            raise self.policy_exc
        return {"Policy": json.dumps(self.policy)}

    def get_bucket_versioning(self, Bucket):
        return {"Status": "Enabled", "MFADelete": "Enabled"}

    def get_bucket_lifecycle_configuration(self, Bucket):
        if self.lifecycle_exc:
            raise self.lifecycle_exc
        return {"Rules": [{"Transition": {"Days": 90, "StorageClass": "GLACIER"}}]}

    def get_bucket_encryption(self, Bucket):
        return {"ServerSideEncryptionConfiguration":
                {"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}

    def get_bucket_logging(self, Bucket):
        return {"LoggingEnabled": {"TargetBucket": self.log_bucket, "TargetPrefix": "p/"}}

    def get_bucket_acl(self, Bucket):
        return {"Grants": [{"Permission": "READ",
                            "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]}

    def get_object_acl(self, Bucket, Key):
        return {"Grants": [{"Permission": "READ", "Grantee": {"ID": "abc"}}]}

    def get_paginator(self, name):
        outer = self

        class _P:
            def paginate(self, Bucket):
                return [{"Contents": [{"Key": "a.txt"}]}]

        return _P()


@pytest.fixture
def mod(tmp_path, monkeypatch):
    """Import the module fresh with a clean CWD (it opens a log file at import)."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["check-permissions.py"])
    spec = importlib.util.spec_from_file_location("check_permissions", SRC)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _run(mod, capsys, client):
    mod.main(s3_client=client)
    return capsys.readouterr().out


def test_access_denied_is_not_reported_as_a_missing_policy(mod, capsys):
    """The core defect: a check that never ran must not look like a clean check."""
    out = _run(mod, capsys, FakeS3(policy_exc=client_error("AccessDenied")))

    assert "does not have a policy" not in out, (
        "AccessDenied was reported as 'does not have a policy'"
    )
    assert "COULD NOT BE COMPLETED" in out
    assert "audit-target" in out
    assert "AccessDenied" in out, "the reason must be shown, not swallowed"


def test_access_denied_suppresses_the_clean_summary(mod, capsys):
    out = _run(mod, capsys, FakeS3(policy_exc=client_error("AccessDenied")))

    assert "No permission issues found.\n" not in out
    assert "audit is INCOMPLETE" in out


def test_genuine_missing_policy_is_still_reported(mod, capsys):
    """A real NoSuchBucketPolicy is a finding and must survive the change."""
    out = _run(mod, capsys, FakeS3(policy_exc=client_error("NoSuchBucketPolicy")))

    assert "does not have a policy" in out


def test_lifecycle_access_denied_is_also_unverified(mod, capsys):
    out = _run(mod, capsys, FakeS3(lifecycle_exc=client_error("AccessDenied",
                                                              "GetBucketLifecycleConfiguration")))

    assert "COULD NOT BE COMPLETED" in out
    assert "3.1.7-1" in out, "the failing requirement must be named"


def test_malformed_policy_is_unverified_not_silently_ignored(mod, capsys):
    """A KeyError from the parsing logic used to vanish into a bare except."""
    out = _run(mod, capsys, FakeS3(policy={"Statement": [{"Action": "s3:*"}]}))

    assert "COULD NOT BE COMPLETED" in out
    assert "KeyError" in out


def test_fully_compliant_account_still_reports_clean(mod, capsys):
    out = _run(mod, capsys, FakeS3())

    assert "COULD NOT BE COMPLETED" not in out
    assert "No permission issues found." in out


def test_no_bare_except_clauses_remain():
    src = SRC.read_text(encoding="utf-8")
    bare = [
        (n, l) for n, l in enumerate(src.splitlines(), 1)
        if l.strip() == "except:"
    ]
    assert not bare, f"bare except clauses remain: {bare}"


def test_module_is_importable():
    """The IndentationError at line 74 made the auditor unusable."""
    compile(SRC.read_text(encoding="utf-8"), str(SRC), "exec")