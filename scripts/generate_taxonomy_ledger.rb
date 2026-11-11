#!/usr/bin/env ruby
# frozen_string_literal: true

# SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
# SPDX-License-Identifier: MIT OR Apache-2.0

require "rbconfig"
require "fileutils"

root = File.expand_path("..", __dir__)
taxonomy_root = ENV.fetch("REALLYME_IDENTITY_TAXONOMY_ROOT", File.expand_path("../identity-taxonomy", root))
advisory_root = File.join(root, "references", "taxonomy-advisory")
default_output = File.join(root, "results", "local", "taxonomy-coverage", "conformance-ledger.json")
FileUtils.mkdir_p(File.dirname(default_output))
arguments = [
  RbConfig.ruby,
  File.join(taxonomy_root, "scripts", "generate_repository_conformance_ledger.rb"),
  "--repository", "reallyme/identity-conformance",
  "--consumer-root", root,
  "--inventory", File.join(taxonomy_root, "conformance", "inventory", "requirements.json"),
  "--evidence-map", File.join(advisory_root, "conformance-evidence.yaml"),
  "--artifact-map", File.join(advisory_root, "conformance-artifacts.yaml"),
  "--output", default_output,
  *ARGV
]
exec(*arguments)
