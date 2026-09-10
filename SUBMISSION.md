# Publishing the paper

Two steps: compile a PDF, then submit it. Neither needs a LaTeX install.

---

## Step 1: get a PDF

The paper is **IEEEtran conference format**, two-column, and compiles to **7 pages** on US Letter.
No bibtex run is needed: the bibliography is a `thebibliography` block in the source.

**Locally** (verified 2026-09-10 on TeX Live 2023):

```
cd paper && pdflatex posea.tex && pdflatex posea.tex
```

Twice matters — the theorem, section and citation cross-references resolve on the second pass. A
clean build reports 7 pages with no overfull boxes and no undefined references; if you see either,
something in the source changed.

Debian/Ubuntu needs `texlive-latex-base texlive-latex-recommended texlive-fonts-recommended
texlive-publishers texlive-latex-extra` (IEEEtran lives in `texlive-publishers`, `microtype` in
`texlive-latex-extra`).

**Overleaf** (free, browser, no install) if you would rather not install TeX: New Project → Blank
Project, delete the sample `main.tex`, upload `paper/posea.tex`, Recompile. IEEEtran and every
other package used (`microtype`, `booktabs`, `cite`, `url`, `hyperref`, `amsmath`, `amssymb`) are
preinstalled there.

Check before submitting: no table splits across a column break, the author block reads how you
want it, and the two figures-free tables (`tab:gap`, `tab:attacks`) land near their text. The
author block currently says *Jan Kučera, NADO, admin@bismuth.cz* — change it if you want a
different affiliation.

`paper/abstract.txt` is the abstract as plain text, generated from the source, for pasting into
submission forms. It is **1,884 characters**, deliberately under arXiv's 1,920-character limit, so
one version works on every venue.

---

## Step 2: submit

### Primary venue: IACR Cryptology ePrint Archive

**eprint.iacr.org**

1. Register for an account (free). Registration is separate from submission.
2. Submit a paper. You will be asked for:

   - **Title:** Proof of Secure Element Attestation: Sybil Resistance from Hardware Scarcity
     Rather Than Cost
   - **Author:** Jan Kučera (UTF-8, with the caron. The form states that names with accents
     must be UTF-8, not TeX codes or HTML entities)
   - **Email:** admin@bismuth.cz (publicly visible, permanently)
   - **Affiliation:** leave blank, or NADO if you want one shown
   - **Abstract:** paste from the paper, plain text, no LaTeX markup
   - **Keywords** (the form enforces: comma separated, each phrase at most 40 characters, no
     LaTeX, **120 characters total**):

     `Sybil resistance, remote attestation, TPM, WebAuthn, secure element, commit-reveal, blockchain`

     That is 95 characters. `TPM` and `commit-reveal` were added for the CA-free enrolment, which
     is what a reader searching for this work is most likely to be searching for; "proof of
     personhood" was dropped because the paper explicitly does *not* claim it.
   - **Category:** Applications
   - **Publication info:** Published nowhere else
   - **License:** CC BY (Creative Commons Attribution) --- irrevocable, chosen once
   - **PDF**

### Hard requirements checked against the live form (2026-09-09)

- The PDF **must contain the author email address**. The form states it explicitly. The paper
  now carries `admin@bismuth.cz` in the author block; a PDF compiled before that change is
  non-compliant.
- Not anonymous: title, author name and contact address on the first page. Satisfied.
- Must fit A4 or US Letter. IEEEtran defaults to `letterpaper`, and the built PDF measures
  612×792 pt (US Letter). Satisfied.
- Abstract is entered as plain text in the form. HTML is rejected; LaTeX math is rendered via
  MathJax. Copying from the compiled PDF often produces invalid UTF-8 — paste `paper/abstract.txt`
  instead, which is generated from the source with the markup stripped.

### The rule that removes the second attempt

> "Once withdrawn, the paper cannot be resurrected and follow-up versions of the same work will
> not be accepted later as another paper."

There is no retry. A withdrawn paper cannot be resubmitted, and neither can a later version of
the same work. This is a stronger constraint than a rejection, and it is the reason to check the
PDF before submitting rather than after.

3. Submissions are screened by editors before appearing. Expect a few days, not minutes.

**Set expectations honestly.** ePrint's scope is cryptology. This paper does not propose or
analyse a cryptographic primitive; it argues a systems result (per-identity rules cannot resist
identity farming) and gives a protocol built from existing primitives — the contribution is the
observation that a TPM credential blob is deterministic in its inputs, which lets ledger ordering
replace an issuer's signature. That is closer to ePrint's scope than the first version of this
paper was, since it is a protocol result with a security argument rather than only a deployment
report, but a screener could still judge it out of scope. That would not be a negative judgement
on the work.

Once posted, an ePrint entry is permanent. It can be revised or withdrawn, but not deleted.

### Fallback, or parallel: arXiv, cs.CR

**arxiv.org**, category **cs.CR** (Cryptography and Security).

Broader scope, and a systems-security paper sits comfortably there. The friction is that a
first-time submitter may need an **endorsement** from an established arXiv author in the same
category, which can take time to arrange.

Submitting to both is allowed and normal.

### Third option: just host it

Put the PDF on nadochain.com and link it from the repo. Instant, no gatekeeping.

This is worth doing regardless of the above, but understand what it does not buy: the reason to
go through ePrint or arXiv is a stable citable identifier and the presumption of seriousness that
comes with the venue. That is the entire strategic point of writing the paper. A self-hosted PDF
is a blog post with equations.

---

## After it is up

- Link it from the `posea` README, the NADO README, and the Bitcointalk PoSEA thread.
- It is the credential that changes how other channels receive the project. A journalist or a
  technical reader who files NADO under "altcoin" reclassifies it as "mechanism" once there is a
  paper, and the project travels with it.
- The open problem is the hook, and it now has published work attached to it — TPM-FAIL, faulTPM
  and the Samsung TrustZone result are all cited in §XI, and faulTPM targets a vendor whose root
  the deployment pins. If someone engages with the question of whether any of those generalises
  beyond physical access, that is worth more than any coverage, including if the answer is that
  the assumption fails.
- The CA-free construction is the part most likely to be reused by people who do not care about
  this chain: it applies to any system with an agreed ordering and a need to attest TPMs the
  platform will not certify. `SPEC.md` §9 is written to be implementable without reading the
  paper.
