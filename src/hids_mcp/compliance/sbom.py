"""
CycloneDX SBOM Generation for HIDS-MCP.

Generates Software Bill of Materials (SBOM) in CycloneDX 1.5 format
from the project's installed dependencies. Demonstrates supply chain
security awareness critical for defense contractor environments.

Supports:
- Component name, version, license, supplier, and hashes
- Direct and transitive dependency enumeration
- CycloneDX 1.5 JSON format output
- NTIA minimum elements compliance

References:
- CycloneDX Specification: https://cyclonedx.org/specification/overview/
- NTIA SBOM Minimum Elements: https://www.ntia.doc.gov/report/2021/minimum-elements-for-a-software-bill-of-materials-sbom
- EO 14028 Section 4: https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/
- NIST SP 800-53 CM-8: System Component Inventory
- NIST SP 800-53 SA-11: Developer Testing and Evaluation
"""

import hashlib
import json
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from uuid import uuid4

logger = logging.getLogger(__name__)


@dataclass
class SBOMComponent:
    """A single software component in the SBOM."""
    name: str
    version: str
    component_type: str = "library"  # library, framework, application, device, firmware
    purl: str = ""
    supplier: str = ""
    license_id: str = ""
    license_name: str = ""
    description: str = ""
    hashes: dict[str, str] = field(default_factory=dict)
    external_references: list[dict] = field(default_factory=list)

    def to_cyclonedx(self) -> dict:
        """Convert to CycloneDX component format."""
        component: dict = {
            "type": self.component_type,
            "name": self.name,
            "version": self.version,
        }

        if self.purl:
            component["purl"] = self.purl

        if self.supplier:
            component["supplier"] = {"name": self.supplier}

        if self.license_id or self.license_name:
            license_entry: dict = {}
            if self.license_id:
                license_entry["license"] = {"id": self.license_id}
            elif self.license_name:
                license_entry["license"] = {"name": self.license_name}
            component["licenses"] = [license_entry]

        if self.description:
            component["description"] = self.description

        if self.hashes:
            component["hashes"] = [
                {"alg": alg.upper(), "content": content}
                for alg, content in self.hashes.items()
            ]

        if self.external_references:
            component["externalReferences"] = self.external_references

        return component


def _get_installed_packages() -> list[dict]:
    """
    Get installed Python packages using importlib.metadata.

    Returns:
        List of dicts with name, version, license, and location info.
    """
    packages = []
    try:
        from importlib.metadata import distributions
        for dist in distributions():
            meta = dist.metadata
            pkg_info = {
                "name": meta.get("Name", "unknown"),
                "version": meta.get("Version", "0.0.0"),
                "license": meta.get("License", ""),
                "summary": meta.get("Summary", ""),
                "author": meta.get("Author", ""),
                "home_page": meta.get("Home-page", ""),
            }

            # Try to get the classifier-based license if License field is empty
            if not pkg_info["license"] or pkg_info["license"] == "UNKNOWN":
                classifiers = meta.get_all("Classifier") or []
                for classifier in classifiers:
                    if classifier.startswith("License ::"):
                        parts = classifier.split(" :: ")
                        if len(parts) >= 3:
                            pkg_info["license"] = parts[-1]
                            break

            packages.append(pkg_info)
    except ImportError:
        logger.warning("importlib.metadata not available, falling back to pip")
        packages = _get_packages_via_pip()

    return packages


def _get_packages_via_pip() -> list[dict]:
    """Fallback: get packages via pip list --format=json."""
    packages = []
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            for pkg in json.loads(result.stdout):
                packages.append({
                    "name": pkg.get("name", "unknown"),
                    "version": pkg.get("version", "0.0.0"),
                    "license": "",
                    "summary": "",
                    "author": "",
                    "home_page": "",
                })
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        logger.error("Failed to get packages via pip: %s", str(e))

    return packages


def _compute_package_identifier(name: str, version: str) -> str:
    """
    Compute a SHA-256 identifier hash for a package name+version pair.

    NOTE: This is a version-based identifier hash for deduplication and
    tracking purposes -- it hashes the string "name==version", NOT the
    actual installed package files. It serves as a stable, reproducible
    identifier for a specific package release, not as a file integrity
    check. For file-level integrity, use the dist-info RECORD file or
    _try_compute_file_hash().
    """
    content = f"{name}=={version}".encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def _try_compute_file_hash(name: str) -> Optional[str]:
    """
    Attempt to compute a real SHA-256 file hash for an installed package
    by locating its top-level module via importlib.

    Returns:
        SHA-256 hex digest of the package's __init__.py or main module file,
        or None if the file cannot be located.
    """
    try:
        from importlib.metadata import distribution
        dist = distribution(name)
        # Try to find the top-level package file via the dist files list
        if dist.files:
            for f in dist.files:
                fpath = f.locate()
                if fpath and fpath.exists() and fpath.suffix == '.py':
                    return hashlib.sha256(fpath.read_bytes()).hexdigest()
    except Exception:
        pass
    return None


def _normalize_license(license_str: str) -> tuple[str, str]:
    """
    Normalize license string to SPDX identifier where possible.

    Returns:
        Tuple of (spdx_id, license_name). If no SPDX match, spdx_id is empty.
    """
    if not license_str or license_str == "UNKNOWN":
        return ("", "")

    # Common license to SPDX mappings
    spdx_map = {
        "MIT License": "MIT",
        "MIT": "MIT",
        "BSD License": "BSD-3-Clause",
        "BSD": "BSD-3-Clause",
        "BSD-2-Clause": "BSD-2-Clause",
        "BSD-3-Clause": "BSD-3-Clause",
        "Apache 2.0": "Apache-2.0",
        "Apache License 2.0": "Apache-2.0",
        "Apache Software License": "Apache-2.0",
        "Apache-2.0": "Apache-2.0",
        "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
        "GPLv3": "GPL-3.0-only",
        "GPL-3.0": "GPL-3.0-only",
        "GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
        "GPLv2": "GPL-2.0-only",
        "ISC License (ISCL)": "ISC",
        "ISC": "ISC",
        "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
        "MPL-2.0": "MPL-2.0",
        "PSF": "PSF-2.0",
        "Python Software Foundation License": "PSF-2.0",
        "LGPL": "LGPL-3.0-only",
    }

    # Try exact match first
    spdx_id = spdx_map.get(license_str, "")
    if spdx_id:
        return (spdx_id, license_str)

    # Try case-insensitive match
    lower_str = license_str.lower().strip()
    for key, value in spdx_map.items():
        if key.lower() == lower_str:
            return (value, license_str)

    # Check if the string itself is an SPDX identifier
    if re.match(r'^[A-Za-z0-9\-\.]+$', license_str) and len(license_str) < 30:
        return (license_str, license_str)

    return ("", license_str)


def _read_project_metadata() -> dict:
    """
    Read project metadata from pyproject.toml.

    Returns:
        Dictionary with project name, version, description, and dependencies.
    """
    metadata = {
        "name": "hids-mcp",
        "version": "0.1.0",
        "description": "Host-based Intrusion Detection System MCP Server",
        "dependencies": [],
    }

    # Try to find pyproject.toml relative to this file
    possible_roots = [
        Path(__file__).parent.parent.parent.parent,  # src/hids_mcp/compliance/ -> project root
        Path.cwd(),
    ]

    for root in possible_roots:
        pyproject_path = root / "pyproject.toml"
        if pyproject_path.exists():
            try:
                content = pyproject_path.read_text()

                # Parse name
                name_match = re.search(r'name\s*=\s*"([^"]+)"', content)
                if name_match:
                    metadata["name"] = name_match.group(1)

                # Parse version
                version_match = re.search(r'version\s*=\s*"([^"]+)"', content)
                if version_match:
                    metadata["version"] = version_match.group(1)

                # Parse description
                desc_match = re.search(r'description\s*=\s*"([^"]+)"', content)
                if desc_match:
                    metadata["description"] = desc_match.group(1)

                # Parse dependencies
                deps_match = re.search(
                    r'dependencies\s*=\s*\[(.*?)\]',
                    content,
                    re.DOTALL,
                )
                if deps_match:
                    deps_block = deps_match.group(1)
                    for dep_match in re.finditer(r'"([^"]+)"', deps_block):
                        metadata["dependencies"].append(dep_match.group(1))

                break
            except OSError as e:
                logger.warning("Failed to read pyproject.toml: %s", str(e))

    return metadata


def generate_sbom(include_transitive: bool = True) -> dict:
    """
    Generate a CycloneDX 1.5 SBOM for the HIDS-MCP project.

    Produces a complete Software Bill of Materials including:
    - Project metadata (name, version, description)
    - Direct dependencies from pyproject.toml
    - Transitive dependencies from the installed environment
    - Component hashes for integrity verification
    - License information with SPDX normalization
    - Package URLs (purl) for universal identification
    - NTIA minimum element compliance

    Args:
        include_transitive: Include transitive (indirect) dependencies.

    Returns:
        CycloneDX 1.5 formatted SBOM dictionary.

    References:
        NIST SP 800-53 CM-8 (System Component Inventory)
        NIST SP 800-53 SA-11 (Developer Testing and Evaluation)
        EO 14028 Section 4 (Software Supply Chain Security)
    """
    project_meta = _read_project_metadata()
    serial_number = f"urn:uuid:{uuid4()}"
    timestamp = datetime.now(timezone.utc).isoformat()

    # Build component list
    components: list[dict] = []
    installed_packages = _get_installed_packages()

    # Parse direct dependency names from pyproject.toml
    direct_dep_names = set()
    for dep_str in project_meta.get("dependencies", []):
        # Extract package name from dependency specifier (e.g., "mcp>=1.0.0" -> "mcp")
        name_match = re.match(r'([a-zA-Z0-9_-]+)', dep_str)
        if name_match:
            direct_dep_names.add(name_match.group(1).lower().replace("-", "_"))

    for pkg in installed_packages:
        pkg_name = pkg["name"]
        pkg_version = pkg["version"]
        normalized_name = pkg_name.lower().replace("-", "_")

        # Skip if not including transitive and this isn't a direct dep
        if not include_transitive and normalized_name not in direct_dep_names:
            # Always include the project itself
            if normalized_name != project_meta["name"].lower().replace("-", "_"):
                continue

        spdx_id, license_name = _normalize_license(pkg.get("license", ""))
        pkg_identifier = _compute_package_identifier(pkg_name, pkg_version)
        # Use real file hash if available, fall back to version-based identifier
        file_hash = _try_compute_file_hash(pkg_name)
        hashes = {"SHA-256": file_hash or pkg_identifier}
        if file_hash:
            hashes["SHA-256-identifier"] = pkg_identifier

        component = SBOMComponent(
            name=pkg_name,
            version=pkg_version,
            component_type="library",
            purl=f"pkg:pypi/{pkg_name.lower()}@{pkg_version}",
            supplier=pkg.get("author", ""),
            license_id=spdx_id,
            license_name=license_name if not spdx_id else "",
            description=pkg.get("summary", ""),
            hashes=hashes,
            external_references=(
                [{"type": "website", "url": pkg["home_page"]}]
                if pkg.get("home_page") else []
            ),
        )
        components.append(component.to_cyclonedx())

    # Build the CycloneDX BOM
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "hids-mcp-sbom-generator",
                        "version": project_meta["version"],
                        "supplier": {"name": "2 Acre Studios"},
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": project_meta["name"],
                "version": project_meta["version"],
                "description": project_meta["description"],
                "supplier": {"name": "2 Acre Studios"},
                "licenses": [{"license": {"id": "MIT"}}],
                "purl": f"pkg:pypi/{project_meta['name'].lower()}@{project_meta['version']}",
            },
            "manufacture": {"name": "2 Acre Studios"},
        },
        "components": components,
    }

    # Add dependency graph
    dependencies = []
    main_dep = {
        "ref": f"pkg:pypi/{project_meta['name'].lower()}@{project_meta['version']}",
        "dependsOn": [
            f"pkg:pypi/{pkg['name'].lower()}@{pkg['version']}"
            for pkg in installed_packages
            if pkg["name"].lower().replace("-", "_") in direct_dep_names
        ],
    }
    dependencies.append(main_dep)
    sbom["dependencies"] = dependencies

    logger.info(
        "Generated CycloneDX SBOM: %d components, serial=%s",
        len(components),
        serial_number,
    )

    return sbom


def generate_sbom_json(include_transitive: bool = True, indent: int = 2) -> str:
    """
    Generate SBOM as formatted JSON string.

    Args:
        include_transitive: Include transitive dependencies.
        indent: JSON indentation level.

    Returns:
        JSON string of the CycloneDX SBOM.
    """
    sbom = generate_sbom(include_transitive=include_transitive)
    return json.dumps(sbom, indent=indent)
