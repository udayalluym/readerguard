# Baseline comparison

Hidden-content attacks (visible-injection baseline excluded) and clean files. *Block* = readerguard `safe:false`, DocFirewall BLOCK, PhantomLint hidden phrase found. *Flag* = block or warn/FLAG.

| format | n | readerguard block / flag | DocFirewall (balanced) block / flag | DocFirewall (strict) block / flag | readerguard (strict sample) block / flag | PhantomLint block / flag |
|---|---|---|---|---|---|---|
| pdf | 420 | 93% / 100% | 0% / 56% | 0% / 59% | 93% / 100% | 29% / 29% |
| html | 320 | 84% / 84% | 0% / 97% | 0% / 97% | 84% / 84% | 16% / 16% |
| docx | 140 | 86% / 93% | 0% / 72% | 0% / 71% | 86% / 93% | 0% / 0% |
| pptx | 120 | 83% / 92% | 0% / 100% | 0% / 100% | 83% / 92% | 0% / 0% |
| xlsx | 120 | 83% / 92% | 0% / 89% | 0% / 92% | 83% / 92% | 0% / 0% |
| markdown | 120 | 83% / 83% | 0% / 98% | 0% / 100% | 83% / 83% | 0% / 0% |
| svg | 40 | 100% / 100% | 0% / 38% | 0% / 38% | 100% / 100% | 0% / 0% |
| image | 60 | 78% / 80% | 0% / 20% | 0% / 20% | 80% / 80% | 0% / 0% |
| all | 1340 | 87% / 92% | 0% / 76% | 0% / 76% | 87% / 91% | 13% / 13% |

Clean files (false alarms):

| format | n | readerguard block / flag | DocFirewall (balanced) block / flag | DocFirewall (strict) block / flag | readerguard (strict sample) block / flag | PhantomLint block / flag |
|---|---|---|---|---|---|---|
| pdf | 196 | 0% / 1% | 0% / 53% | 0% / 50% | 0% / 0% | 0% / 0% |
| html | 136 | 0% / 0% | 0% / 92% | 0% / 90% | 0% / 0% | 0% / 0% |
| docx | 136 | 0% / 0% | 0% / 19% | 0% / 20% | 0% / 0% | 0% / 0% |
| pptx | 45 | 0% / 0% | 0% / 100% | 0% / 100% | 0% / 0% | 0% / 0% |
| xlsx | 119 | 0% / 0% | 0% / 26% | 0% / 25% | 0% / 0% | 0% / 0% |
| markdown | 136 | 0% / 0% | 0% / 97% | 0% / 100% | 0% / 0% | 0% / 0% |
| svg | 10 | 0% / 0% | 0% / 0% | 0% / 0% | 0% / 0% | 0% / 0% |
| image | 60 | 0% / 0% | 0% / 0% | 0% / 0% | 0% / 0% | 0% / 0% |
| all | 838 | 0% / 0% | 0% / 55% | 0% / 51% | 0% / 0% | 0% / 0% |

By payload (all formats, block rate):

- readerguard: instruction 100%, fact 71%, active 100%; unsupported/errored attacked files 0
- DocFirewall (balanced): instruction 0%, fact 0%, active 0%; unsupported/errored attacked files 0
- DocFirewall (strict): instruction 0%, fact 0%, active 0%; unsupported/errored attacked files 0
- readerguard (strict sample): instruction 100%, fact 70%, active 100%; unsupported/errored attacked files 0
- PhantomLint: instruction 27%, fact 0%, active 0%; unsupported/errored attacked files 645
