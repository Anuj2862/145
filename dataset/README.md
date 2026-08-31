# Dataset Directory

**Scope:** Storage and manifest catalog for public PCAP captures and lab-generated attack/benign traffic scenarios with ground-truth JSON files.

## Development Dataset Format

During early development (Milestone 1), this directory will temporarily house synthetic/mock data. 
- Mocks will generate basic `FlowEvent` objects (5-tuple metrics, counters) to unblock feature extraction and detector development.
- Mock `FlowEvent` objects are passed directly into the `FeatureExtractor` to produce normalized `FeatureVector`s.

## Future Integration

- Real public datasets (e.g. PCAPs of DDoS or C2 traffic) will be integrated in later milestones.
- These datasets will be processed by Member 1's ingestion pipeline to produce real `FlowEvent`s.
- No payload or decrypted content is required, as the pipeline relies purely on packet metadata, flow statistics, and passively observable headers (DNS/TLS).
