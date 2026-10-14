from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum


class Operation(str, Enum):
    INSPECT = 'inspect'
    EXTRACT = 'extract'
    ANALYZE = 'analyze'


@dataclass(frozen=True)
class JobContract:
    job_id: str
    operation: Operation

    @classmethod
    def from_json(cls, raw: str) -> 'JobContract':
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError('job contract must be an object')
        job_id = data.get('job_id')
        if not isinstance(job_id, str) or not job_id.strip():
            raise ValueError('job_id is required')
        return cls(job_id=job_id, operation=Operation(data['operation']))

    def to_json(self) -> str:
        return json.dumps({'job_id': self.job_id, 'operation': self.operation.value}, sort_keys=True)
