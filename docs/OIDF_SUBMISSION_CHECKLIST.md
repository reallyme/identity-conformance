# OIDF certification submission checklist

Use this checklist before an OIDF submission. An authorized ReallyMe
representative performs the legal and administrative steps. Repository checks
prepare evidence; OIDF decides certification.

## Release identity

- [ ] Immediately before the final matrix run, check the OIDF GitLab tags and
  confirm that `conformance-suite.lock.json` names the newest `release-v*` tag
  and its exact commit. Regenerate both module snapshots if the pin changes.
- [ ] The deployment manifest names the submitting legal entity, product, and
  immutable product version exactly as they will appear in the submission.
- [ ] Every deployed verifier, wallet, and issuer artifact is content-addressed
  in the deployment manifest and was built from the commits in
  the caller-supplied product component BOM.
- [ ] The evidence index passes validation without changing an
  artifact.
- [ ] The public disclosure review confirms that exports contain no keys,
  tokens, personal data, transaction content, or internal-only endpoints.

## Official hosted runs

- [ ] Both OpenID4VP verifier profiles completed on the official production
  OIDF conformance server with `PASSED` modules and only the exact
  source-classified `REVIEW` modules permitted by the locked result policy.
- [ ] All four OpenID4VP wallet profiles, including both Browser API profiles,
  completed under the same `PASSED`/source-classified `REVIEW` policy, with any
  other result rejected.
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
  rather than an automated test result.
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

Self-certification and independent assessment are different claims. Keep the
same evidence bundle for an external assessor, together with build provenance,
threat models, dependency reviews, incident-response records, and remediation
evidence. Do not call the product independently certified unless the authorized
scheme and assessor have completed the assessment and issued a result.

Record the responsible human, submission date, OIDF response, and certificate
identifier in the controlled release record. Do not add credentials, payment
codes, signatures, or private correspondence to this repository.
