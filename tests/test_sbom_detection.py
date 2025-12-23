import json

from deployment.security import SBOMGenerator


def test_detect_dependencies_from_pyproject_and_package_lock(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = [
  "requests>=2.31.0",
  "numpy==1.26.0"
]

[project.optional-dependencies]
dev = ["pytest>=7.0.0"]
        """,
        encoding="utf-8",
    )

    package_lock = tmp_path / "package-lock.json"
    package_lock.write_text(
        json.dumps(
            {
                "dependencies": {
                    "lodash": {"version": "4.17.21"},
                    "dev-only": {"version": "1.0.0", "dev": True},
                }
            }
        ),
        encoding="utf-8",
    )

    generator = SBOMGenerator()
    deps = generator._detect_dependencies(str(tmp_path))

    python = {d.name: d for d in deps if d.ecosystem == "pip"}
    npm = {d.name: d for d in deps if d.ecosystem == "npm"}

    assert python["requests"].version == "2.31.0"
    assert python["numpy"].version == "1.26.0"
    assert python["pytest"].version == "7.0.0"
    assert "lodash" in npm and npm["lodash"].version == "4.17.21"
    # dev dependency still captured but marked direct
    assert npm["dev-only"].version == "1.0.0"


def test_detect_dependencies_from_go_mod(tmp_path):
    go_mod = tmp_path / "go.mod"
    go_mod.write_text(
        """
module example.com/app

require (
    github.com/pkg/errors v0.9.1
    github.com/sirupsen/logrus v1.9.0
)

require golang.org/x/net v0.24.0
""",
        encoding="utf-8",
    )

    generator = SBOMGenerator()
    deps = generator._detect_dependencies(str(tmp_path))

    go_deps = {d.name: d for d in deps if d.ecosystem == "go"}

    assert go_deps["github.com/pkg/errors"].version == "v0.9.1"
    assert go_deps["github.com/sirupsen/logrus"].version == "v1.9.0"
    assert go_deps["golang.org/x/net"].version == "v0.24.0"
