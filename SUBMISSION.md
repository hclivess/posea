# Publishing the paper

Two steps: compile a PDF, then submit it. Neither needs a LaTeX install.

---

## Step 1: get a PDF

**Overleaf** (free, browser, no install) is the fastest route.

1. Go to overleaf.com, create a free account.
2. New Project → Blank Project.
3. Delete the sample `main.tex`, upload `paper/posea.tex` from this repo.
4. Click **Recompile**. It uses only standard packages (`amsmath`, `amssymb`, `amsthm`,
   `booktabs`, `hyperref`, `geometry`), all preinstalled.
5. Download PDF.

If you would rather compile locally: install TeX Live (Linux/macOS) or MiKTeX (Windows), then
`pdflatex paper/posea.tex` twice. Twice matters, because the theorem cross-reference resolves on
the second pass.

Check before submitting: the observation is numbered and referenced correctly, the device-class
table is not split across a page break, and the author block reads how you want it to. It
currently says *Jan Kucera, nadochain.com* — change it if you would rather use a different name
or add an affiliation.

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
   - **Keywords:** `Sybil resistance`, `remote attestation`, `trusted execution environment`,
     `WebAuthn`, `consensus`, `blockchain`, `proof of personhood`, `secure element`
   - **Category:** Applications
   - **Publication info:** Published nowhere else
   - **License:** CC BY (Creative Commons Attribution) --- irrevocable, chosen once
   - **PDF**

### Hard requirements checked against the live form (2026-09-09)

- The PDF **must contain the author email address**. The form states it explicitly. The paper
  now carries `admin@bismuth.cz` in the author block; a PDF compiled before that change is
  non-compliant.
- Not anonymous: title, author name and contact address on the first page. Satisfied.
- Must fit A4 or US Letter. The document class is `a4paper`. Satisfied.
- Abstract is entered as plain text in the form. HTML is rejected; LaTeX math is rendered via
  MathJax. Copying from the compiled PDF often produces invalid UTF-8, so paste from the
  `.tex` source instead.

### The rule that removes the second attempt

> "Once withdrawn, the paper cannot be resurrected and follow-up versions of the same work will
> not be accepted later as another paper."

There is no retry. A withdrawn paper cannot be resubmitted, and neither can a later version of
the same work. This is a stronger constraint than a rejection, and it is the reason to check the
PDF before submitting rather than after.

3. Submissions are screened by editors before appearing. Expect a few days, not minutes.

**Set expectations honestly.** ePrint's scope is cryptology. This paper does not propose or
analyse a cryptographic primitive; it argues a systems result (per-identity rules cannot resist
identity farming) and describes an admission mechanism built on existing attestation standards.
Blockchain and protocol papers do appear on ePrint regularly, so it is a reasonable submission,
but a screener could judge it out of scope. That would not be a negative judgement on the work.

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
- The open problem in the abstract is the hook. If someone engages with the secure-element key
  extraction question, that is worth more than any coverage, including if the answer is that the
  assumption fails.
