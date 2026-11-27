# Data protection impact assessment (GDPR Art. 35): outline

Status: draft outline. Not legal advice. The controller completes it, consults the people
concerned where practical, and records the decision. Generic for systems that record audio continuously;
A hypothetical platform with continuous household audio, transcription, speaker identification and hosted users is the example.

## 0. Why a DPIA is required here

At least two criteria of the EDPB/WP29 list apply (WP248 rev.01), which makes a DPIA required in practice:

- systematic monitoring: continuous recording in a home captures everyone present;
- special categories: voice processed to identify speakers may be biometric data (Art. 9(1));
- vulnerable data subjects and imbalance: visitors, children, employees (cleaners, carers) who cannot
  meaningfully object in the moment;
- innovative use of technology: automatic transcription, summaries, speaker matching;
- large scale over time: years of audio per recorder (about 8,640 chunks per day per device).

## 1. Description of the processing

- Nature: capture (recorders), transport, storage (encrypted object store via s3vault), transcription,
  diarization and speaker identification, summaries, search; deletion and backup.
- Scope: data categories, data subjects (tenants, space members, third parties), volume (objects per day,
  years kept), geography (hosts and provider regions).
- Context: household and hosted users; expectations of visitors; children present?
- Purposes: as in the records of processing (ROP-1).
- Data flow diagram: recorder -> backend -> s3vault (proxy host) -> object store (EU region) and the
  follower copy; key service on a separate host; transcription workers; backups.

## 2. Necessity and proportionality

- Legal basis per purpose and per data subject group (consent of tenants; legitimate interests for third
  parties with the balancing test written down; explicit consent for speaker identification).
- Data minimisation: can recording pause automatically (presence, schedule, a visible mute)? Is raw audio
  needed after transcription, or can it be deleted after N days? Can speaker identification be off by default?
- Storage limitation: retention table of the records of processing, including the cap for forever tiers.
- Transparency: notices for visitors (signage, a spoken or written notice, an easy way to ask for deletion).
- Rights: how each right is served (records of processing, section 5); third-party erasure requests.
- Processors: agreements and transfer safeguards (`processor-agreements.md`).

## 3. Risks to data subjects

For each risk: likelihood, severity, existing measures, residual risk.

| Risk | Source | Notes |
|---|---|---|
| Disclosure of intimate conversations | breach of the proxy host (sees plaintext in RAM), stolen device, insider | the proxy host provider is a processor of plaintext |
| Identification of third parties by voice | speaker identification | special-category data; consent rarely available |
| Covert monitoring of household members or staff | continuous recording | power imbalance; employment law may apply |
| Data kept longer than stated | backups, follower copies, forever tiers | mitigated by per-tenant keys, escrow limit, ledger replay |
| Erased data reappearing after a restore | backups restored without the ledger | mitigated by the ledger replay in every restore path |
| Loss of data (availability) | lost keys, provider failure | two offline root copies, escrow before rotation |
| Metadata leakage to the store provider | object sizes and timing reveal speech activity | accepted by the operator; documented in the threat model |
| Inaccurate transcripts or attributions | ASR and diarization errors | rectification path; no decisions based on them |

## 4. Measures

List the measures from the records of processing (section 4) and anything added because of this DPIA:
recording indicators, default-off speaker identification, shorter raw-audio retention, visitor notice,
access reviews, breach response plan (Art. 33/34: 72-hour notification), regular erasure drills.

## 5. Outcome

- Residual risk per item and overall.
- If high residual risk remains: prior consultation of the supervisory authority (Art. 36).
- Sign-off (controller), date, review date (at least yearly, and on every material change: a new purpose,
  a new processor, a new data category such as location).
