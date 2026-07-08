# Changelog

All notable changes to the PortFootprint project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-07-08

### Added
- **Core Multi-threaded TCP Connect Scanner Engine**: Implemented connection scheduling pool setups and target validations (Phase 1).
- **Service Discovery & Protocol Fingerprinting**: Added dynamic decorator-based registry and modular fingerprinters supporting HTTP, HTTPS/TLS, SSH, FTP, SMTP, DNS, IRC, and Databases (MySQL, PostgreSQL, Redis, MongoDB) (Phase 2).
- **Professional Reporting Engine**: Added JSON, CSV, and premium standalone HTML report format exporters (Phase 3).
- **Statistics & History**: Integrated execution performance speed metrics, local history storage databases, and scans comparative reports (Phase 3).
- **Logging & Configurations**: Extended options to load defaults from `config.json` configurations files and support files logging (Phase 3).
- **Tests**: Reached solid code verification coverage across all CLI, scanner, reporting, and services modules.
