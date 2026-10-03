# Current validation record: 2026-10-02

Current version: 1.0.1. Python 3.14.6 passed 6/6 local unit/regression tests. A wheel was built with Python 3.12, installed in a fresh Python 3.12 virtual environment outside the checkout, and its CLI was invoked from outside the source directory.

Installed CLI read local pip PE32/PE32+ launcher bytes; samples were not executed. The wheel contains five package source files plus license and metadata; each packaged source file was byte-compared with the current checkout.

Wheel SHA-256: `e783c566375974e5ddc68fdaf62a4e1f811ceed0a153fbcfc90a3340929ad7c7`.

The tests cover normal declaration/redaction behavior, input-size limits, direct symlinks, non-regular files and the specific incomplete/error cases found during source review. All credentials are synthetic; PE samples were existing local pip PE32/PE32+ launcher files and were only read.

Header bits are declarations only. No Windows loader, signature, relocation directory, CFG load configuration or runtime enforcement test was performed. The exact public commit and corresponding GitHub workflow are verified separately in the portfolio index.

CVP eligibility remains OPEN: these technical checks do not establish an actual safeguards-affected task, applicant identity, organization binding or an Anthropic decision.
