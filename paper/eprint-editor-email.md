To: eprint-editor@iacr.org
From: admin@bismuth.cz
Subject: Submissions xxxx/111651 and xxxx/111764 — which criterion?

Dear editors,

Two submissions of the same paper, "Proof of Secure Element Attestation Without a Certificate Authority", have been declined with the archive's three general criteria quoted and no specific reason. Between the two I rewrote the abstract and introduction so the construction is the first sentence, consolidated the contributions, and defined the terms the threat model used without definition; nothing in the content changed.

The contribution is a protocol result: TPM2_MakeCredential's credential blob is a deterministic function of its (seed, object name, secret) triple, so a possession challenge issued once can be recomputed offline by every verifier afterwards, and the privacy CA that TPM key certification has always required is replaced by an agreed publication order across k beacon-drawn challengers under commit-reveal. Section V argues that the ordering is the proof and names the single object attribute it rests on; Section IV-E quantifies a weakening of the collusion bound (the draw can be resampled); Section VII completes the enrolment on a physical AMD firmware TPM.

I would be grateful for one sentence naming the criterion that was decisive, or, if the judgement is scope, saying so. I will not resubmit a third time without knowing which, and a scope answer would send me to arXiv cs.CR without further cost to you.

Thank you for your time and for maintaining the archive.

Jan Kučera
admin@bismuth.cz
