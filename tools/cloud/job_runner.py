from __future__ import annotations

import argparse
from pathlib import Path

from tools.vibebot.cloud_job import JobContract
from tools.cloud.result_contract import ResultContract, ResultStatus


def run(job: JobContract) -> ResultContract:
    # Cloud v1 deliberately proves the dispatch/result boundary before wiring
    # artifact download and individual analyzer adapters. Never shell-expand
    # user input here; operation is already constrained by JobContract.
    return ResultContract(
        job_id=job.job_id,
        status=ResultStatus.COMPLETED,
        operation=job.operation,
        summary=f"validated Vibe job accepted for operation {job.operation}",
        outputs=[],
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--job", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    job = JobContract.from_json(Path(args.job).read_text(encoding="utf-8"))
    result = run(job)
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(result.to_json(), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
