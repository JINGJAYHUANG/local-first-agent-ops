#!/usr/bin/env python3
from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
from pathlib import Path

ARCHIVE_SHA256 = "6a05cbfafbbad39137a281b3f91c2a04f571be47e59b0712f68fb3da5206413a"
FILE_HASHES = {
  ".github/ISSUE_TEMPLATE/bug.yml": "d7ef7bd66b3198206bd79f5976b99d03756c3f09c4b5741c8a541be40f16a3ad",
  ".github/ISSUE_TEMPLATE/policy-change.yml": "52d9b614054e1d66aa87e3bca11a114bd57250d8a9bc870705b232a890c21629",
  ".github/pull_request_template.md": "cb5cbfd532e18476e1b45bfb5a7d5decb390c0bd4a4055ac30591555ad700e34",
  ".gitignore": "62415dd8a8a0512846076e6e7855ab95a10f8ba07ad0e9a1c995dad5908865ee",
  "AGENTS.md": "838cc7642735323baa7a1cd93e97f9917805b3b1e5ad6f1b66b2c72939a7d914",
  "CHANGELOG.md": "302cb54a073429f3e06a9fb5c9b153e4a1d7fdef77e10c7c7c40af24f0eeb8f9",
  "CITATION.cff": "cb1d3efed6f0aa753f230889003cf40eb0e37388d9eb53a3f24ff5ef0104290f",
  "CODE_OF_CONDUCT.md": "6a6c6f5109e454752421c4030aab19e0ea51189ee07437b7f56a86b2e0845117",
  "CONTRIBUTING.md": "52b4468243a6bd167005d16b71d35b202fc8fb44e3c1d7f267945523f9e79172",
  "DEVELOPMENT_DISCLOSURE.md": "43e809018532b1906fc4d392b5b82c68e27a5e9e89e75672fa5c0292987cab98",
  "LICENSE": "4501081464347448ddda0514e59178762bb851605fb79cff8f08af0b86eeb687",
  "MANIFEST.in": "a563c5f9b71229e18110f5b14d04f0c4be44ba9f81110ee83d66c61da81c25f0",
  "README.md": "7ebd18ed9b1de09ca8f17200b5242415e7fddfb56e96e42698946233a7c44ea8",
  "ROADMAP.md": "d405d36870423352bf0085ac0f8a1b393161ef4d05b82a7dc6b7a0a1a18570ca",
  "SECURITY.md": "ff1ee93ba5f6db91ac1960c7965a29081541120f8e7216f1f02213229959da74",
  "docs/README.zh-CN.md": "1b911e151ff231644af26e8645902708984b580d266566034507a9ea2abdd6ca",
  "docs/architecture.md": "df4a556ee68a17685183eb1d9575539f31c318ccf5bfbd83ce11439967601492",
  "docs/audit-log.md": "f554ca19016ca56031599967e5419d372ca2fbcb161e1b937f0ba7d697766340",
  "docs/automation-selection.md": "ba1c700f74fc709ea62b1fd43749e00f14c65444a1dde53028c01f7db09bb23b",
  "docs/design-decisions.md": "e01f8feab4e5806b2a1142edcefa04f8f36b5f35efb002133f2e6b6d83d7a4ca",
  "docs/limitations.md": "039139572580c1c921d82c873a360a9ff24b494916b221717498888817ab9f86",
  "docs/openclaw-mapping.md": "8eaffc9e66f696cd4a543a5812d95797fd42257c3a867040e5aff385f1474a94",
  "docs/policy-reference.md": "5914330c65589c0678c3d0c1997b693359783059c52899dd65d90a99545b830c",
  "docs/release-notes/v0.1.0.md": "e3dd9c5a0e853a7da85e8af963ed8d702bb7c7e7a84eaa80eb8f53029800bd4e",
  "docs/security-model.md": "3dc4ae8c99a5fde38a7125bf4f4559f9036ed53c37b3b0691272637a5992dfa3",
  "docs/threat-model.md": "4529b57ab1cadc87fbb77f497d3c3cc5b372c61638e68ace4a1f319a1923d837",
  "docs/two-machine-pattern.md": "ca168e95f762b345fc2026e80bba5af1a2b922f19f77728d74b3c2ff90d9b677",
  "examples/README.md": "f4ae7bb4fb8d86678fb8cc979fb7c17f78fc0a4d1ae821c3f7dc55ce9592300b",
  "examples/configs/safe-lab.json": "414828203303790ef42adf2c80c77886e80f4833bc703469a1d2a4a872315792",
  "examples/configs/two-machine-safe.json": "10d047f09656a54a4e11b22f477bc7e5872f8d0e64693de16803150526be7e4a",
  "examples/expected/safe-lab-decisions.json": "42185d0507fcd7a60623c04930d05a6a41e3dd57295fd11113996d39339c8ab7",
  "examples/requests/safe-lab-tasks.jsonl": "0ae6fdca5d51f5b2b4090243bb6d1887008d10a0f15cf2a28a04bded7e461813",
  "examples/requests/task-delete-denied.json": "b54242dc74656f6983b1340cdfa1aa585147ad19d9b44a848f4a2248c11445d8",
  "examples/requests/task-public-research.json": "0b2d19c66e183d9b8393a58265427e50fb865075f2c4d4261430f922c559f9f4",
  "examples/requests/task-send-approved.json": "38c59d74516a3d39cff72fd14887f9174038462838c1eb50e47d37c10373d426",
  "pyproject.toml": "e64f4ad09a71ab746a29dbb41122d1b611b53803c8a8ca9b2c5af544e37662bb",
  "schemas/README.md": "6e3c70212e2313fb0f82abac6e9c03d8fcaeec5f3ccaec5426f424000f2547aa",
  "schemas/audit-record.schema.json": "1f36c2888e4b2730fccaf691d128cf69b74bb26e685368023081171846e122c0",
  "schemas/config.schema.json": "83ad34dc64c178ecb66cd930fe7a482092e5cf29085c9fa74ebc437622bebfbb",
  "schemas/decision.schema.json": "bb9f4d9d749d3f84fce4f0291c9cc66878f23855fdfe3e7177c5ec70f2baa574",
  "schemas/request.schema.json": "c991f02b436999662951aa28f01505153ec93948168413b839f6d04fcaef6122",
  "scripts/check_docs.py": "e7f06349707814def7065a42913650ab894b62fd67778c9e045bcfd0ff31e3ca",
  "scripts/check_examples.py": "746b0151e0d24d156f09e9b13a1a61df176190a24ce01f05fb269fe56e90261c",
  "scripts/public_audit.py": "e0ee0d385b2fb70893874b79d9233ad37876006940116b4ce2a763bf97551b87",
  "scripts/run_release_gate.py": "2d586c2e96838d25d153a414be08a980c6b16e949eff26903c31783842f9fc08",
  "src/local_first_agent_ops/__init__.py": "7588616594a77eb1bdbed1b54d8fba09a664f191208ac12167b7bf7b156d80f7",
  "src/local_first_agent_ops/__main__.py": "7649eb01cf5a61aa1cc8ea441093371a09cadba135384892412f2d91c23e3905",
  "src/local_first_agent_ops/audit.py": "6ee038d076d78248346059fa6078496c90ae20408755075b1cfbc5b8e052c731",
  "src/local_first_agent_ops/automation.py": "75d4e7ad606d0558cc3bed76d9ec819c404357c564ab1ee8f6aed82bb1ffdc40",
  "src/local_first_agent_ops/cli.py": "d5f663502666cff120405d29984998656346004f33fdc45b87372f952a0612cb",
  "src/local_first_agent_ops/config.py": "ba25c21289f92961c2871a0562687d0f8302ced8c01303acff1c51b5e755647b",
  "src/local_first_agent_ops/constants.py": "6006364c0244956618925304197789ea1428370392ce1a6c1b6e2544428de1b4",
  "src/local_first_agent_ops/data/safe-lab-tasks.jsonl": "0ae6fdca5d51f5b2b4090243bb6d1887008d10a0f15cf2a28a04bded7e461813",
  "src/local_first_agent_ops/data/safe-lab.json": "414828203303790ef42adf2c80c77886e80f4833bc703469a1d2a4a872315792",
  "src/local_first_agent_ops/errors.py": "c31ac871ff4bfcb5d688ba5698d62487179c660888b7735abae5c96ba81a0b96",
  "src/local_first_agent_ops/models.py": "5aab19ae3d7f77896de70225a08285660451c2f655f719fba258e3179b01c3f4",
  "src/local_first_agent_ops/policy.py": "86c85adf5a9f7739a46c65c6bc43bcd70d07c9d99b889a0ee2b79cb8bb92a3f",
  "src/local_first_agent_ops/request.py": "a15eb1486ebd0875834533535467557d8ac3f3b10598167722f38243bd9214d7",
  "src/local_first_agent_ops/router.py": "80a0898d4154ce2cf39e1cf76bd900503960187194a816c471ef4132478f8c6a",
  "src/local_first_agent_ops/simulator.py": "06e31cff5913fd81807f316201392362032377098002919ea0b7bcfcdb952c0b4",
  "templates/README.md": "7d01f81f3975aec91a68d81862bc67e03779626e5e3b36a00ccae63314222093",
  "templates/permission-matrix.json": "e6bce3e57afe2e665f77f2e0a7e14f2673fc13c149e68000e7df2700f9c10adc",
  "templates/workspace/AGENTS.md": "96c1ba7dd27ffb241a4f9200522475cc694d8df3ca0bc6a7c6bc2c1675f78a4e",
  "templates/workspace/HEARTBEAT.md": "08176268c9322c5a00b10c1aa2da01a37fe04fbcd7dc64976352b63af25c413a",
  "templates/workspace/IDENTITY.md": "a1b00f29d7b15e9296f571f23b92f9cc354beb6369101cc1405807d8b9fb1f1c",
  "templates/workspace/SOUL.md": "13d3ad719475106fa1fcdadff2cc26f198805f82f800be2d7e177af75b3f41ef",
  "templates/workspace/TOOLS.md": "b3cfb4734844fc284f7608c03ac3724372212012284cdf15469c0b6c6387a5ce",
  "templates/workspace/USER.md": "3005af648fe537d1e02e85af9785712b028eeb4a9b116dc9015355f5757660aa",
  "tests/helpers.py": "1218d7252772777578c9b6cfc57d5d699a6d71df5e382b7056ce2dd2767527b4",
  "tests/test_audit.py": "d41215f6e709a3369330d230338ff348061e2549bd680080871691875461d67b",
  "tests/test_automation.py": "aa7a4a2292b69279cd17964fb915cbb2766381b11ab1231ef5574893394fb9ba",
  "tests/test_cli.py": "d2883638126dd3790ef3a31572c68e3bcf6c45016cdf1ab1c13f7a423cf48db6",
  "tests/test_config.py": "e35a37946442d68fb50bea074ba8de2862029127172915a5e2c2e4917905f459",
  "tests/test_policy.py": "2124174a8d78ba30dd4c7ecce5afd20bd5a7e160fcb6e657e7fa1091e5f59050",
  "tests/test_publication.py": "04b8f775cc1381314d86378644196e8dd0aa72a1caa92d92550a5f9af643c1f5",
  "tests/test_router.py": "9ae57438d6254f388d70a8f855bd4a29c1cc9c6bf8ba6e8276da0dcd73552423",
  "tests/test_simulator.py": "05bcbf75078bac7f16be5dc7195efce77b7d2ffbe053c30f1b88bf19f8f7f2ca"
}
PAYLOAD = """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"""


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    archive = base64.b64decode(PAYLOAD.encode("ascii"), validate=True)
    actual_archive = hashlib.sha256(archive).hexdigest()
    if actual_archive != ARCHIVE_SHA256:
        raise SystemExit(
            f"bootstrap archive hash mismatch: {actual_archive} != {ARCHIVE_SHA256}"
        )

    observed: dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as bundle:
        members = bundle.getmembers()
        for member in members:
            path = Path(member.name)
            if (
                member.name.startswith("/")
                or ".." in path.parts
                or not member.isfile()
                or member.issym()
                or member.islnk()
            ):
                raise SystemExit(f"unsafe bootstrap member: {member.name}")
            if member.name not in FILE_HASHES:
                raise SystemExit(f"unexpected bootstrap member: {member.name}")
            handle = bundle.extractfile(member)
            if handle is None:
                raise SystemExit(f"missing payload for: {member.name}")
            data = handle.read()
            digest = hashlib.sha256(data).hexdigest()
            if digest != FILE_HASHES[member.name]:
                raise SystemExit(f"file hash mismatch: {member.name}")
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            observed[member.name] = digest

    if observed != FILE_HASHES:
        missing = sorted(set(FILE_HASHES) - set(observed))
        raise SystemExit(f"bootstrap file set mismatch; missing={missing}")

    print(
        json.dumps(
            {
                "status": "ok",
                "files": len(observed),
                "archive_sha256": ARCHIVE_SHA256,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
