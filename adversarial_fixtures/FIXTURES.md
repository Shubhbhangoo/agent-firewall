# Adversarial fixtures

Each file is a real artifact produced by the v1.8 flight recorder,
then deliberately damaged in exactly one documented way. The
expected verification status is asserted by
`test_v1_8_fixtures.py`.

| fixture | damage | expected status |
| --- | --- | --- |
| bad-checkpoint-signature.afw | bad-checkpoint-signature.afw | failed |
| deleted-event.afw | deleted-event.afw | failed |
| forged-tail-event.afw | forged-tail-event.afw | failed |
| incomplete-session.afw | incomplete-session.afw | incomplete |
| redacted-session.afw | redacted-session.afw | redacted |
| reordered-events.afw | reordered-events.afw | failed |
| tampered-event.afw | tampered-event.afw | failed |
| truncated-json.afw | truncated-json.afw | unverifiable |
| verified.afw | verified.afw | verified |
| wrong-recorder-identity.afw | wrong-recorder-identity.afw | failed |

Regenerate with: `.venv\\Scripts\\python adversarial_fixtures\\generate.py`
