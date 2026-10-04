#!/usr/bin/env python3
"""Fail closed unless the exact source has a complete successful main-push CI run.

Read-only GitHub Actions API calls use the existing GH_TOKEN. All required jobs
must belong to one latest successful attempt; after partial reruns, rerun all jobs.
"""
import argparse
import json
import re
import subprocess

WORKFLOW_PATH = ".github/workflows/ci.yml"
WORKFLOW_NAME = "Build and Test"
REQUIRED_JOBS = {
    f"Build and Test ({os}, {framework})": ("Build", "Run tests")
    for os in ("ubuntu-latest", "windows-latest", "macos-latest")
    for framework in ("net8.0", "net9.0", "net10.0")
}
REQUIRED_JOBS.update({
    "Extract Build Configuration": ("Extract configuration",),
    "Verify coverage report": ("Validate coverage and publish summary",),
    "Code Quality": ("Build (with warnings as errors)", "Check formatting"),
    "Dependency Review": ("Dependency Review",),
})
REQUIRED_JOBS.update({
    f"Validate Release Package ({os})": (
        "Test package validation gates",
        "Restore locked dependencies and fail closed on audit errors",
        "Build, pack, validate and reproduce the Release payload",
        "Smoke-test packaged public APIs on each runtime",
    )
    for os in ("ubuntu-latest", "windows-latest")
})


def select_run(workflow, runs, commit, repository):
    if (workflow.get("path") != WORKFLOW_PATH or workflow.get("name") != WORKFLOW_NAME
            or workflow.get("state") != "active" or not isinstance(workflow.get("id"), int)):
        raise ValueError("CI workflow identity is missing, changed, or inactive")
    expected = {"workflow_id": workflow["id"], "path": WORKFLOW_PATH, "name": WORKFLOW_NAME,
                "event": "push", "head_branch": "main", "head_sha": commit}
    matching = [run for run in runs if all(run.get(key) == value for key, value in expected.items())
                and run.get("head_repository", {}).get("full_name") == repository]
    if not matching:
        raise ValueError("No exact-source Build and Test push/main run exists")
    # Do not allow an older success to hide a later failed or pending run.
    run = max(matching, key=lambda item: (item["id"], item["run_attempt"]))
    if (run.get("status") != "completed" or run.get("conclusion") != "success"
            or not isinstance(run.get("id"), int) or run["id"] <= 0
            or not isinstance(run.get("run_attempt"), int) or run["run_attempt"] <= 0):
        raise ValueError("Latest exact-source CI run/attempt is not completed successfully")
    return run


def validate_jobs(run, jobs):
    names = [job.get("name") for job in jobs]
    if len(names) != len(set(names)) or not REQUIRED_JOBS.keys() <= set(names):
        raise ValueError("CI attempt is missing required jobs or has duplicate job names; rerun all jobs")
    for job in jobs:
        if (job.get("run_id") != run["id"] or job.get("head_sha") != run["head_sha"]
                or job.get("status") != "completed" or job.get("conclusion") != "success"):
            raise ValueError(f"CI job is not successful for this source/run: {job.get('name')}")
        steps = {step.get("name"): step for step in job.get("steps", [])}
        for name in REQUIRED_JOBS.get(job["name"], ()):
            step = steps.get(name, {})
            if step.get("status") != "completed" or step.get("conclusion") != "success":
                raise ValueError(f"Required CI step did not pass: {job['name']} / {name}")


def github_api(endpoint, paginate=False):
    command = ["gh", "api", endpoint]
    if paginate:
        command += ["--paginate", "--slurp"]
    return json.loads(subprocess.check_output(command, text=True))


def verify_ci(repository, commit):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Expected a repository owner/name and full commit SHA")
    base = f"repos/{repository}/actions"
    workflow = github_api(f"{base}/workflows/ci.yml")
    endpoint = f"{base}/workflows/{workflow['id']}/runs?branch=main&event=push&head_sha={commit}&per_page=100"
    pages = github_api(endpoint, paginate=True)
    run = select_run(workflow, [run for page in pages for run in page["workflow_runs"]], commit, repository)
    pages = github_api(f"{base}/runs/{run['id']}/attempts/{run['run_attempt']}/jobs?per_page=100", paginate=True)
    jobs = [job for page in pages for job in page["jobs"]]
    if not pages or len(jobs) != pages[0]["total_count"]:
        raise ValueError("Incomplete CI jobs response")
    validate_jobs(run, jobs)
    # Re-read the latest run after fetching jobs, catching a rerun started meanwhile.
    pages = github_api(endpoint, paginate=True)
    latest = select_run(workflow, [run for page in pages for run in page["workflow_runs"]], commit, repository)
    if (latest["id"], latest["run_attempt"]) != (run["id"], run["run_attempt"]):
        raise ValueError("CI run/attempt changed during verification; retry after CI finishes")
    print(f"Verified {len(jobs)} successful exact-source CI jobs: run {run['id']}, attempt {run['run_attempt']}, commit {commit}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    args = parser.parse_args()
    try:
        verify_ci(args.repository, args.commit)
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Release CI gate failed: {error}\n")


if __name__ == "__main__":
    main()
