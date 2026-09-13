# Cover note to editors (resubmission)

Dear editors,

This is a revised resubmission of a paper previously entered as xxxx/111651 and returned with the
archive's general criteria. The title in that submission's metadata was mistyped; it is entered correctly
here.

The paper makes one protocol observation and builds an enrolment on it. TPM2_MakeCredential's credential
blob is a deterministic function of its (seed, object name, secret) triple, so a possession challenge
issued once can be recomputed offline by every verifier afterwards. An inherently interactive proof
becomes an artifact anyone can re-derive, and the privacy certificate authority that TPM attestation has
always required is replaced by an agreed publication *order*: four messages, with a commit–reveal across
k challengers drawn by a public beacon. No signing key and no long-lived secret exist anywhere in the
construction. Definition 1 (§IV) states what is being constructed; §V argues that the ordering is the
proof and names the single object attribute it rests on; §IV-E quantifies a weakening of the collusion
bound (the draw can be resampled) that a reader would otherwise take on trust; §VII completes the
enrolment on a physical AMD firmware TPM on a live chain.

The application is admission to a permissionless system. Work, stake and space each price an identity
per unit of resource, and any rule priced per identity costs an adversary holding n identities exactly
what it costs an honest participant holding one. Attested silicon adds a fourth resource: one identity
per secure element, verified against pinned vendor roots with no online service. The paper is explicit
that this does not make identities scarce, only expensive, and that a device farm is the mechanism's
ASIC; what it changes is the constant, measured in deployment at roughly 1,000 of 1,191 identities held
by two or three browser-farm operators taking 42% of emission.

Relative to the returned version, the abstract and introduction now lead with the construction, the
contributions are stated in four claims each pointing at the section that argues it, and the two terms
the threat model previously used without definition (beacon, draw weight) and the window parameter W are
defined where they are first used. No claims have been added.

The implementation, specification, pinned roots and tests are public at github.com/hclivess/posea.

Thank you for your time.

Jan Kučera
