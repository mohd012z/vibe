from tools.cloud.job_contract import JobContract, Operation
from tools.cloud.job_runner import run
from tools.cloud.result_contract import ResultStatus


def test_unimplemented_job_fails_closed():
    result = run(JobContract(job_id='fixture-1', operation=Operation.INSPECT))
    assert result.status is ResultStatus.FAILED
    assert result.outputs == []
    assert result.error == 'ANALYZER_NOT_IMPLEMENTED'


def test_job_contract_roundtrip():
    job = JobContract.from_json('{"job_id":"fixture-2","operation":"extract"}')
    assert JobContract.from_json(job.to_json()) == job
