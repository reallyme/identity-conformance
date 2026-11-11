# OIDF certification submission checklist

This checklist separates machine-verifiable evidence from the legal and
administrative acts that an authorized ReallyMe representative must perform.
Passing repository gates or pre-submission runs is not itself certification.

## Release identity

- [ ] Immediately before the final matrix run, query the upstream OIDF GitLab
  tag list and confirm `conformance-suite.lock.json` still names the newest
  released `release-v*` tag and its exact commit; regenerate both module
  snapshots whenever that pin changes.
- [ ] The deployment manifest names the submitting legal entity, product, and
  immutable product version exactly as they will appear in the submission.
- [ ] Every deployed verifier, wallet, and issuer artifact is content-addressed
  in the deployment manifest and was built from the commits in
  `components.lock.json`.
- [ ] The retained evidence index validates without modifying any artifact.
- [ ] The public disclosure review confirms that exports contain no keys,
  tokens, personal data, transaction content, or internal-only endpoints.

## Official hosted runs

- [ ] Both OpenID4VP verifier profiles completed on the official production
  OIDF conformance server with `PASSED` modules and only the exact
  source-classified `REVIEW` modules permitted by the locked result policy.
- [ ] All four OpenID4VP wallet profiles, including both Browser API profiles,
  completed under the same fail-closed `PASSED`/source-classified `REVIEW`
  policy.
- [ ] All four OpenID4VCI issuer profiles passed.
- [ ] All six OpenID4VCI wallet profiles passed, including issuer-initiated
  by-value and by-reference credential offers.
- [ ] Each plan used a unique alias and the **Publish for certification** action
  was completed only after its final passing run.
- [ ] One unmodified OIDF export ZIP per profile is retained with the evidence
  index; all ZIP digests match.

## Self-certification submission

- [ ] An authorized representative has reviewed the
  [OIDF Certification Terms and Conditions](https://openid.net/wordpress-content/uploads/2015/03/OpenID-Certification-Terms-and-Conditions.pdf)
  and understands that self-certification is a legally binding attestation,
  not an automated test result.
- [ ] The representative has confirmed the current
  [submission instructions](https://openid.net/certification/how-to-submit-your-certification-request/)
  and [fees](https://openid.net/certification/fees/).
- [ ] The submission portal metadata exactly matches the retained deployment
  manifest and evidence bundle.
- [ ] The correct member payment code or certification fee is available.
- [ ] The authorized representative, not an engineering automation, signs the
  declaration sent through the OIDF signature workflow.
- [ ] The final public listing and certification marks are not used until OIDF
  confirms acceptance.

## Independent assessment

Self-certification and independent assessment are distinct claims. Preserve the
same immutable evidence bundle for an external assessor, together with build
provenance, threat models, dependency reviews, incident-response records, and
remediation evidence. Do not describe the product as independently certified
unless an authorized scheme and assessor have completed that process and issued
the corresponding result.

Record the responsible human, submission date, OIDF response, and certificate
identifier in the controlled release record. Do not add credentials, payment
codes, signatures, or private correspondence to this repository.
