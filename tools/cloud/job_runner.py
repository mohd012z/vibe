from __future__ import annotations

import argparse
from pathlib import Path

from tools.cloud.job_contract import JobContract
from tools.cloud.result_contract import ResultContract, ResultStatus


def run(job: JobContract) -> ResultContract:
    return ResultContract(
        job_id=job.job_id,
        status=ResultStatus.FAILED,
        operation=job.operation.value,
        summary='No analysis engine executed; no output was produced.',
        outputs=[],
        error='ANALYZER_NOT_IMPLEMENTED',
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--job', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    job = JobContract.from_json(Path(args.job).read_text(encoding='utf-8'))
    result = run(job)
    output = Path(args.out)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(result.to_json(), encoding='utf-8')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
